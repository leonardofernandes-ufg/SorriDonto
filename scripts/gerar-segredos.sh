#!/bin/sh
# Gera os arquivos de segredo usados pelo docker-compose (ficam em secrets/, fora do Git).
set -eu
cd "$(dirname "$0")/.."
mkdir -p secrets
umask 077
[ -f secrets/data_key ] || { openssl rand -base64 32 > secrets/data_key; echo "criada: secrets/data_key (FAÇA BACKUP: sem ela os dados cifrados não abrem)"; }
[ -f secrets/admin_password ] || { openssl rand -base64 18 | tr -d '/+=\n' > secrets/admin_password; echo "criada: secrets/admin_password"; }
# o usuário do contêiner (uid 10001) precisa ler os arquivos; somente leitura para ele
if [ "$(id -u)" = "0" ]; then chown 10001:10001 secrets/data_key secrets/admin_password; else
  echo "aviso: rode com sudo para dar a posse dos segredos ao uid 10001, ou use: sudo chown 10001:10001 secrets/*"; fi
chmod 400 secrets/data_key secrets/admin_password
