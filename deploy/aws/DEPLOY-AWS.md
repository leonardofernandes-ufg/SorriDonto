# Subir o SorriDonto na AWS (Docker em uma EC2)

Arquitetura simples e barata, adequada para o trabalho da disciplina e para um piloto:

```
Internet ──HTTPS (TLS 1.2/1.3)──▶ EC2 ┬─ contêiner caddy  (certificado Let's Encrypt, HSTS)
                                       └─ contêiner app    (Node, rede interna, sem porta pública)
                                            └─ volume /data (SQLite, colunas sensíveis cifradas)
                       disco EBS cifrado (KMS) · segredos no Secrets Manager (KMS) · backups no S3 (SSE-KMS)
```

> Nenhum comando abaixo foi executado por mim: não há credenciais da AWS nesta sessão. Eles criam recursos
> que **geram custo** (veja a estimativa em "Quanto custa", cerca de US$ 21/mês em São Paulo). Troque `REGIAO`, `CONTA`, `DOMINIO` etc.

## Por que Docker?

Sim, faz sentido: a imagem fixa o ambiente (Node 22), roda sem privilégios, com sistema de arquivos só de
leitura, sem capabilities e com limite de memória e processos. O mesmo `docker compose up` roda no seu
computador e na AWS. O Caddy fica na frente cuidando do HTTPS, e o app não expõe porta nenhuma.

## Como os dados e as comunicações são protegidos

| Camada | Proteção |
|---|---|
| Navegador ↔ servidor | HTTPS com TLS 1.2/1.3 (Caddy), HSTS, redirecionamento de HTTP para HTTPS, cookie `Secure`. |
| Dados no banco | **AES-256-GCM por campo**: CPF, data de nascimento, telefone, e-mail, endereço e observações do paciente; e-mail e mensagem dos interessados. CPF e e-mail têm índice cego (HMAC) para busca exata e unicidade. |
| Nome do paciente | Fica legível no banco para permitir busca por parte do nome; é protegido pelo disco cifrado (abaixo). |
| Disco | Volume EBS cifrado com chave KMS. |
| Chave dos dados | Arquivo secreto montado em `/run/secrets` (vem do Secrets Manager, cifrado com KMS); nunca no código, no Git, nem no ambiente do processo. |
| Senhas | `scrypt` com salt (nunca reversível). |
| Backups | Cifrados pelo app (AES-256-GCM) **e** pelo S3 (SSE-KMS), com versionamento e bloqueio de acesso público. |
| Contêiner | Usuário sem privilégios, `read_only`, `cap_drop: ALL`, `no-new-privileges`, limites de CPU/memória. |

Limite honesto: com acesso ao servidor **e** à chave (por exemplo, root na EC2), os dados podem ser lidos.
A criptografia protege contra roubo do disco, do backup ou de um snapshot, e contra vazamento do arquivo do banco.

## Quanto custa (5 usuários por dia, região São Paulo, 24 h por dia)

| Item | US$/mês |
|---|---|
| EC2 `t3.micro` (0,0168/h × 730 h) | 12,26 |
| IPv4 público (0,005/h × 730 h) | 3,65 |
| Disco EBS gp3 de 20 GB (*) | ≈ 3,00 |
| Chave KMS (1,00) + 2 segredos no Secrets Manager (2 × 0,40) (*) | ≈ 1,80 |
| Backups no S3 (poucos MB) e tráfego de saída (poucos MB/dia) | < 0,20 |
| **Total** | **≈ 21 (cerca de R$ 115)** |

Com `t3.small` o total sobe para ≈ US$ 33. Domínio e DNS ficam à parte (um `.com.br` custa algumas dezenas de reais por ano).
Preços de EC2 e IPv4 conferidos em fontes públicas; os itens com (*) são de memória: confirme na
[calculadora da AWS](https://calculator.aws/) com a região **sa-east-1 (São Paulo)**, que é cerca de 60% mais cara que a Virgínia,
mas mantém os dados no Brasil. Contas com o *Free Tier* têm 750 h/mês grátis de IPv4 público nos primeiros 12 meses.
Para 5 acessos por dia o uso de CPU e rede é desprezível: o custo é todo de "manter a máquina ligada".

## Modo Free Tier (apresentação universitária, custo próximo de zero)

Funciona dentro do Free Tier da AWS com estas trocas em relação ao passo a passo completo:

| Item do guia completo | No Free Tier | Perda de proteção |
|---|---|---|
| EC2 `t3.small` | `t3.micro` (confira se é elegível: `aws ec2 describe-instance-types --filters Name=free-tier-eligible,Values=true --query "InstanceTypes[*].InstanceType"`) | nenhuma para poucos usuários |
| Chave KMS própria (≈ US$ 1/mês) | chave gerenciada pela AWS (`aws/ebs`), que o EBS cifrado já usa | você não controla a política da chave |
| Secrets Manager (US$ 0,40 por segredo) | **SSM Parameter Store** `SecureString` (camada padrão, sem custo de armazenamento) | nenhuma relevante |
| S3 com SSE-KMS | SSE-S3 (gratuito) e o backup já sai cifrado pelo app | nenhuma: o arquivo já é cifrado por você |
| Domínio próprio | subdomínio gratuito (veja abaixo) | nenhuma |

**Sobre o Free Tier.** Contas criadas **depois de 15/07/2025** recebem até US$ 200 em créditos e um plano gratuito
de 6 meses (acaba quando os créditos ou o prazo terminam, o que vier primeiro). Contas mais antigas têm 750 h/mês de EC2
elegível e de IPv4 público por 12 meses. Confira em *Billing → Free Tier* qual é o seu caso e **crie um alerta de orçamento**
(AWS Budgets, US$ 5) para não ter surpresa.

**Roteiro (cerca de 30 minutos; faça HOJE, não na hora da apresentação):**
```bash
export AWS_REGION=sa-east-1
# 1) disco cifrado por padrão (chave aws/ebs, sem custo)
aws ec2 enable-ebs-encryption-by-default
# 2) segredos no Parameter Store (cifrados com a chave aws/ssm)
aws ssm put-parameter --name /sorridonto/data-key       --type SecureString --value "$(openssl rand -base64 32)"
aws ssm put-parameter --name /sorridonto/admin-password --type SecureString --value "$(openssl rand -base64 18 | tr -d '/+=\n')"
# guarde a data-key também fora da AWS: sem ela os dados cifrados não abrem
```
3. Crie o papel IAM da EC2 com a política [iam-policy-ec2-freetier.json](iam-policy-ec2-freetier.json) + `AmazonSSMManagedInstanceCore`.
4. Lance a EC2 `t3.micro` (Amazon Linux 2023, gp3 de 20 GB, IMDSv2 obrigatório) com security group **só 80 e 443**, e associe um **IP elástico**.
5. **Nome para o HTTPS.** O Let's Encrypt precisa de um nome DNS. Sem comprar domínio: um subdomínio gratuito do
   [DuckDNS](https://www.duckdns.org) apontando para o IP elástico (`sorridonto.duckdns.org`). Alternativa: `SEU-IP-COM-HIFENS.sslip.io`
   (por exemplo, `54-233-10-20.sslip.io`), que resolve para o próprio IP, mas o limite de emissão de certificados é compartilhado
   com quem mais usa o serviço (não verifiquei o limite atual).
6. Na instância (Session Manager):
```bash
sudo dnf install -y git && git clone https://github.com/leonardofernandes-ufg/SorriDonto.git && cd SorriDonto
printf 'DOMINIO=sorridonto.duckdns.org\nEMAIL_ACME=seu@email.com\nADMIN_EMAIL=admin@sorridonto.local\n' > .env
FONTE_SEGREDOS=ssm bash deploy/aws/instalar-na-ec2.sh
```
7. Abra `https://SEU-NOME`, entre com o administrador (senha = parâmetro `/sorridonto/admin-password`) e cadastre um paciente.

**Plano B para a apresentação:** deixe o sistema rodando também no seu computador (`npm start`, ou `docker compose` com
`DOMINIO=localhost`). Se a internet ou o DNS falharem, você apresenta localmente sem perder nada.

**Depois da nota:** desligue ou termine a instância e libere o IP elástico (IPv4 parado também gera cobrança).

## Passo a passo (versão completa)

### 1. Chave KMS e criptografia padrão do EBS
```bash
export AWS_REGION=sa-east-1
aws kms create-alias --alias-name alias/sorridonto-dados \
  --target-key-id $(aws kms create-key --description "SorriDonto dados" --query KeyMetadata.KeyId --output text)
aws ec2 enable-ebs-encryption-by-default
aws ec2 modify-ebs-default-kms-key-id --kms-key-id alias/sorridonto-dados
```

### 2. Segredos (chave dos dados e senha do primeiro administrador)
```bash
aws secretsmanager create-secret --name sorridonto/data-key       --kms-key-id alias/sorridonto-dados \
  --secret-string "$(openssl rand -base64 32)"
aws secretsmanager create-secret --name sorridonto/admin-password --kms-key-id alias/sorridonto-dados \
  --secret-string "$(openssl rand -base64 18 | tr -d '/+=\n')"
```
**Guarde uma cópia da `data-key` em local seguro e separado** (por exemplo, gerenciador de senhas). Sem ela,
os dados cifrados e os backups não podem ser lidos.

### 3. Bucket de backups
```bash
B=sorridonto-backup-SEU-SUFIXO
aws s3api create-bucket --bucket $B --region $AWS_REGION --create-bucket-configuration LocationConstraint=$AWS_REGION
aws s3api put-public-access-block --bucket $B --public-access-block-configuration BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true
aws s3api put-bucket-versioning --bucket $B --versioning-configuration Status=Enabled
aws s3api put-bucket-encryption --bucket $B --server-side-encryption-configuration \
  '{"Rules":[{"ApplyServerSideEncryptionByDefault":{"SSEAlgorithm":"aws:kms","KMSMasterKeyID":"alias/sorridonto-dados"}}]}'
```
Adicione uma política do bucket que **negue** `aws:SecureTransport = false` (só aceita HTTPS).

### 4. Perfil IAM da EC2 (menor privilégio)
Crie um papel para EC2 com a política [iam-policy-ec2.json](iam-policy-ec2.json) (troque `REGIAO`, `CONTA`, o ID da
chave e o nome do bucket) e anexe a política gerenciada `AmazonSSMManagedInstanceCore` (acesso sem abrir a porta 22).

### 5. Rede e instância
- **Security group**: entrada só nas portas **80** e **443** (TCP; 443 também UDP). **Não abra a 22**: use o *Session Manager* (SSM).
- **EC2**: Amazon Linux 2023, `t3.micro` (1 GB basta para poucos usuários; use `t3.small` se crescer), disco gp3 de 20 GB (cifrado pelo padrão do passo 1), **IMDSv2 obrigatório**
  (`--metadata-options HttpTokens=required,HttpEndpoint=enabled`) e o perfil do passo 4.
- **IP elástico** associado e um registro DNS **A** do seu domínio para ele (o Let's Encrypt precisa disso).

### 6. Instalar e subir (conecte pelo Session Manager)
```bash
sudo dnf install -y git
git clone https://github.com/leonardofernandes-ufg/SorriDonto.git && cd SorriDonto
cp .env.example .env && nano .env      # DOMINIO e EMAIL_ACME
bash deploy/aws/instalar-na-ec2.sh
```
O script instala o Docker, baixa os segredos do Secrets Manager e roda `docker compose up -d --build`.
Na primeira execução o app cria o administrador; a senha é a do segredo `sorridonto/admin-password`.
Acesse `https://SEU-DOMINIO` e confira o cadeado e o redirecionamento de `http://`.

### 7. Backup diário
```bash
(crontab -l 2>/dev/null; echo '0 2 * * * cd /home/ec2-user/SorriDonto && BUCKET=SEU-BUCKET bash deploy/aws/backup-s3.sh >> /var/log/sorridonto-backup.log 2>&1') | crontab -
```
Restaurar: baixe o `.enc`, copie para o contêiner e rode `node scripts/restaurar.js arquivo.enc` com o app parado.
**Teste a restauração** uma vez por mês: backup que nunca foi restaurado não é backup.

### 8. Verificar a segurança no servidor publicado
```bash
TEST_EMAIL=... TEST_SENHA=... BASE_URL=https://SEU-DOMINIO PULAR_DDOS=1 node security/verifica.js
```
(Não rode a parte de inundação contra o ambiente real sem avisar a AWS e sem querer ser bloqueado.)

## Contra DDoS na AWS
O limite por IP do app segura inundação simples. Para ataque distribuído, ponha o **CloudFront + AWS WAF**
(regras gerenciadas e *rate-based*) na frente do domínio: o AWS Shield Standard já protege CloudFront e Elastic IP
sem custo extra. Atrás de CloudFront/ALB, mantenha `TRUST_PROXY=1`.

## Evolução recomendada (e alinhada à disciplina)
SQLite em um único servidor é suficiente para o piloto. Para escalar, migre o banco para **Amazon RDS for PostgreSQL**
(criptografia em repouso com KMS, backups automáticos, Multi-AZ, TLS obrigatório) e rode o app no **ECS Fargate**
atrás de um **ALB** com certificado do **ACM**. O modelo e os papéis da Etapa 4 (`BD/etapa4_seguranca_sorridonto.sql`)
já estão em PostgreSQL.
