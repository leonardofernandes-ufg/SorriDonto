#!/bin/bash
# Cria TUDO que o SorriDonto precisa na AWS, a partir do AWS CloudShell (já logado na sua conta):
#   curl -fsSL https://raw.githubusercontent.com/leonardofernandes-ufg/SorriDonto/main/deploy/aws/provisionar.sh | bash
# Recursos: papel IAM (só Session Manager), security group (80/443), IP elástico, EC2 t3.micro com disco
# cifrado, IMDSv2 obrigatório. A instância instala o Docker, baixa o código do GitHub (repositório público),
# gera os segredos NA PRÓPRIA máquina e sobe o app com HTTPS (nome <ip>.sslip.io, certificado Let's Encrypt).
# Para remover tudo depois: deploy/aws/remover.sh
set -euo pipefail
export AWS_REGION="${AWS_REGION:-sa-east-1}" AWS_PAGER=""
REPO="${REPO:-https://github.com/leonardofernandes-ufg/SorriDonto.git}"
TIPO="${TIPO:-t3.micro}"
NOME=sorridonto

echo ">> Conta/região: $(aws sts get-caller-identity --query Account --output text) / $AWS_REGION"

# --- papel para acessar a máquina pelo Session Manager (sem abrir a porta 22) ---
if ! aws iam get-role --role-name "$NOME-ec2" >/dev/null 2>&1; then
  aws iam create-role --role-name "$NOME-ec2" --assume-role-policy-document '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"ec2.amazonaws.com"},"Action":"sts:AssumeRole"}]}' >/dev/null
  aws iam attach-role-policy --role-name "$NOME-ec2" --policy-arn arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore
fi
if ! aws iam get-instance-profile --instance-profile-name "$NOME-ec2" >/dev/null 2>&1; then
  aws iam create-instance-profile --instance-profile-name "$NOME-ec2" >/dev/null
  aws iam add-role-to-instance-profile --instance-profile-name "$NOME-ec2" --role-name "$NOME-ec2"
  sleep 12   # o perfil leva alguns segundos para ficar disponível
fi

# --- rede: só 80 e 443 ---
VPC=$(aws ec2 describe-vpcs --filters Name=is-default,Values=true --query 'Vpcs[0].VpcId' --output text)
[ "$VPC" != "None" ] || { echo "Não há VPC padrão nesta região."; exit 1; }
SG=$(aws ec2 describe-security-groups --filters Name=group-name,Values="$NOME" Name=vpc-id,Values="$VPC" --query 'SecurityGroups[0].GroupId' --output text)
if [ "$SG" = "None" ]; then
  SG=$(aws ec2 create-security-group --group-name "$NOME" --description "SorriDonto: HTTP e HTTPS" --vpc-id "$VPC" --query GroupId --output text)
  for P in 80 443; do aws ec2 authorize-security-group-ingress --group-id "$SG" --protocol tcp --port $P --cidr 0.0.0.0/0 >/dev/null; done
  aws ec2 authorize-security-group-ingress --group-id "$SG" --protocol udp --port 443 --cidr 0.0.0.0/0 >/dev/null
fi

# --- IP elástico e nome para o HTTPS ---
read -r ALLOC IP < <(aws ec2 allocate-address --domain vpc --query '[AllocationId,PublicIp]' --output text)
DOMINIO="${IP//./-}.sslip.io"
echo ">> IP elástico $IP  ->  https://$DOMINIO"

# --- o que a instância executa na primeira partida ---
USERDATA=$(cat <<UD
#!/bin/bash
exec > /var/log/sorridonto-bootstrap.log 2>&1
set -ex
dnf install -y docker git
systemctl enable --now docker
mkdir -p /usr/local/lib/docker/cli-plugins
curl -fsSL "https://github.com/docker/compose/releases/download/v2.29.7/docker-compose-linux-\$(uname -m)" -o /usr/local/lib/docker/cli-plugins/docker-compose
chmod +x /usr/local/lib/docker/cli-plugins/docker-compose
git clone $REPO /opt/sorridonto
cd /opt/sorridonto
umask 077
mkdir -p secrets
openssl rand -base64 32 > secrets/data_key
openssl rand -base64 18 | tr -d '/+=\n' > secrets/admin_password
chown 10001:10001 secrets/data_key secrets/admin_password
chmod 400 secrets/data_key secrets/admin_password
cat > .env <<ENV
DOMINIO=$DOMINIO
ADMIN_EMAIL=admin@sorridonto.local
BASE_IMAGE=public.ecr.aws/docker/library/node:22-alpine
CADDY_IMAGE=public.ecr.aws/docker/library/caddy:2.8.4-alpine
ENV
docker compose up -d --build
echo BOOTSTRAP-CONCLUIDO
UD
)

AMI=$(aws ssm get-parameter --name /aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64 --query Parameter.Value --output text)
ID=$(aws ec2 run-instances --image-id "$AMI" --instance-type "$TIPO" --iam-instance-profile Name="$NOME-ec2" \
  --security-group-ids "$SG" --metadata-options HttpTokens=required,HttpEndpoint=enabled \
  --block-device-mappings 'DeviceName=/dev/xvda,Ebs={VolumeSize=20,VolumeType=gp3,Encrypted=true,DeleteOnTermination=true}' \
  --user-data "$USERDATA" --tag-specifications "ResourceType=instance,Tags=[{Key=Name,Value=$NOME}]" \
  --query 'Instances[0].InstanceId' --output text)
echo ">> Instância $ID criada; aguardando ficar ativa..."
aws ec2 wait instance-running --instance-ids "$ID"
aws ec2 associate-address --instance-id "$ID" --allocation-id "$ALLOC" >/dev/null

cat <<FIM

============================================================
 Pronto. A instalação dentro da máquina leva de 5 a 8 minutos.
 Endereço:      https://$DOMINIO
 Instância:     $ID   (região $AWS_REGION)
 IP elástico:   $IP   (AllocationId $ALLOC)
 Senha do admin e chave de dados ficam em /opt/sorridonto/secrets/ na instância
 (EC2 > Conectar > Session Manager):  sudo cat /opt/sorridonto/secrets/admin_password
 Guarde uma cópia de data_key fora da AWS: sem ela os dados cifrados não abrem.
============================================================
FIM
