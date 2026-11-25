'use strict';
// Restaura um backup cifrado:  node scripts/restaurar.js arquivo.db.gz.enc [destino.db]
// Pare o servidor antes. Sem a chave de dados correta a restauração falha (nada é gravado).
const fs = require('fs');
const zlib = require('zlib');
const cripto = require('../cripto');

const [origem, destino = process.env.RESTAURAR_PARA || `${cripto.dirDados}/sorridonto.db`] = process.argv.slice(2);
if (!origem) { console.error('Uso: node scripts/restaurar.js arquivo.db.gz.enc [destino.db]'); process.exit(2); }
const banco = zlib.gunzipSync(cripto.decifraBuffer(fs.readFileSync(origem)));
for (const ext of ['', '-wal', '-shm']) fs.rmSync(destino + ext, { force: true });
fs.writeFileSync(destino, banco, { mode: 0o600 });
console.log(`Restaurado em ${destino} (${banco.length} bytes).`);
