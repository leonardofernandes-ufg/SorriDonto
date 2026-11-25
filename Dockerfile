# syntax=docker/dockerfile:1
# Imagem enxuta: o sistema não tem dependências npm, só o Node 22 (SQLite embutido).
ARG BASE_IMAGE=node:22-alpine
FROM ${BASE_IMAGE}

ENV NODE_ENV=production \
    DATA_DIR=/data \
    HOST=0.0.0.0 \
    PORT=3000 \
    TRUST_PROXY=1

WORKDIR /app
COPY package.json server.js api.js db.js cripto.js ./
COPY scripts ./scripts
COPY public ./public

# Usuário sem privilégios (uid fixo, para casar com a permissão dos arquivos de segredo)
RUN addgroup -g 10001 -S app && adduser -u 10001 -S -G app app \
 && mkdir /data && chown app:app /data
USER app

VOLUME /data
EXPOSE 3000

HEALTHCHECK --interval=30s --timeout=3s --start-period=15s --retries=3 \
  CMD node -e "fetch('http://127.0.0.1:3000/').then(r=>process.exit(r.ok?0:1)).catch(()=>process.exit(1))"

CMD ["node", "--max-old-space-size=256", "--disable-proto=delete", "server.js"]
