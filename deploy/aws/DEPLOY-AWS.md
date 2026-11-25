# Subir o SorriDonto na AWS (Docker em uma EC2)

Arquitetura simples e barata, adequada para o trabalho da disciplina e para um piloto:

```
Internet ──HTTPS (TLS 1.2/1.3)──▶ EC2 ┬─ contêiner caddy  (certificado Let's Encrypt, HSTS)
                                       └─ contêiner app    (Node, rede interna, sem porta pública)
                                            └─ volume /data (SQLite, colunas sensíveis cifradas)
                       disco EBS cifrado (KMS) · segredos no Secrets Manager (KMS) · backups no S3 (SSE-KMS)
```

> Nenhum comando abaixo foi executado por mim: não há credenciais da AWS nesta sessão. Eles criam recursos
> que **geram custo** (EC2 `t3.small` ≈ US$ 15/mês, mais disco e IP). Troque `REGIAO`, `CONTA`, `DOMINIO` etc.

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

## Passo a passo

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
- **EC2**: Amazon Linux 2023, `t3.small`, disco gp3 de 20 GB (cifrado pelo padrão do passo 1), **IMDSv2 obrigatório**
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
