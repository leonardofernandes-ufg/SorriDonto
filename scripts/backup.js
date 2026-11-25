'use strict';
// Backup consistente e CIFRADO do banco (AES-256-GCM, mesma chave dos dados).
//   node scripts/backup.js [pasta-destino]      (padrão: <DATA_DIR>/backups)
// Gera sorridonto-AAAAMMDD-HHMMSS.db.gz.enc. Envie-o para o S3 com SSE-KMS (deploy/aws/backup-s3.sh).
const fs = require('fs');
const path = require('path');
const zlib = require('zlib');
const { DatabaseSync } = require('node:sqlite');
const cripto = require('../cripto');

const destino = process.argv[2] || path.join(cripto.dirDados, 'backups');
fs.mkdirSync(destino, { recursive: true, mode: 0o700 });
const agora = new Date().toISOString().replace(/[-:]/g, '').replace(/\..*/, '').replace('T', '-');
const tmp = path.join(destino, `.tmp-${process.pid}.db`);

const db = new DatabaseSync(path.join(cripto.dirDados, 'sorridonto.db'));
db.exec(`VACUUM INTO '${tmp.replace(/'/g, "''")}'`);   // cópia consistente, sem parar o servidor
db.close();
const saida = path.join(destino, `sorridonto-${agora}.db.gz.enc`);
fs.writeFileSync(saida, cripto.cifraBuffer(zlib.gzipSync(fs.readFileSync(tmp))), { mode: 0o600 });
fs.rmSync(tmp);
console.log(saida);
