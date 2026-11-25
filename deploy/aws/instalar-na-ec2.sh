#!/bin/bash
# Prepara uma EC2 (Amazon Linux 2023) para rodar o SorriDonto. Execute como ec2-user, com sudo disponível.
#   1) sudo dnf install -y git   2) git clone <repo> && cd SorriDonto   3) bash deploy/aws/instalar-na-ec2.sh
set -euo pipefail
REGIAO="${AWS_REGION:-sa-east-1}"
SEGREDO_CHAVE="${SEGREDO_CHAVE:-sorridonto/data-key}"
SEGREDO_ADMIN="${SEGREDO_ADMIN:-sorridonto/admin-password}"

sudo dnf install -y docker awscli >/dev/null
sudo systemctl enable --now docker
# plugin do Compose v2
sudo mkdir -p /usr/local/lib/docker/cli-plugins
sudo curl -fsSL "https://github.com/docker/compose/releases/download/v2.29.7/docker-compose-linux-$(uname -m)" -o /usr/local/lib/docker/cli-plugins/docker-compose
sudo chmod +x /usr/local/lib/docker/cli-plugins/docker-compose

# segredos vêm do AWS Secrets Manager (cifrados com KMS) e ficam só em arquivos 0400 do uid 10001
mkdir -p secrets
umask 077
aws secretsmanager get-secret-value --region "$REGIAO" --secret-id "$SEGREDO_CHAVE" --query SecretString --output text > secrets/data_key
aws secretsmanager get-secret-value --region "$REGIAO" --secret-id "$SEGREDO_ADMIN" --query SecretString --output text > secrets/admin_password
sudo chown 10001:10001 secrets/data_key secrets/admin_password
sudo chmod 400 secrets/data_key secrets/admin_password

[ -f .env ] || { echo "Crie o arquivo .env (copie de .env.example) com DOMINIO e EMAIL_ACME e rode de novo."; exit 1; }
sudo docker compose up -d --build
sudo docker compose ps
