#!/bin/bash
# Backup cifrado do banco para o S3 (SSE-KMS). Agende no cron do host, por exemplo, todo dia às 2h:
#   0 2 * * *  cd /home/ec2-user/SorriDonto && BUCKET=meu-bucket-backup bash deploy/aws/backup-s3.sh
set -euo pipefail
: "${BUCKET:?defina BUCKET}"
REGIAO="${AWS_REGION:-sa-east-1}"
# Com CHAVE_KMS definida usa SSE-KMS (chave própria, ~US$ 1/mês); sem ela usa SSE-S3 (gratuito). O arquivo já sai cifrado pelo app.
if [ -n "${CHAVE_KMS:-}" ]; then SSE=(--sse aws:kms --sse-kms-key-id "$CHAVE_KMS"); else SSE=(--sse AES256); fi
arq=$(docker compose exec -T app node scripts/backup.js /data/backups | tail -1)   # já sai cifrado com a chave dos dados
nome=$(basename "$arq")
docker compose cp "app:$arq" "/tmp/$nome"
aws s3 cp "/tmp/$nome" "s3://$BUCKET/sorridonto/$nome" --region "$REGIAO" "${SSE[@]}"
rm -f "/tmp/$nome"
docker compose exec -T app sh -c "ls -1t /data/backups/sorridonto-*.enc | tail -n +8 | xargs -r rm -f"   # mantém só os 7 últimos locais
echo "backup enviado: s3://$BUCKET/sorridonto/$nome"
