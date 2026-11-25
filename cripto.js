'use strict';
/**
 * Criptografia dos dados guardados (em repouso).
 *
 *  - AES-256-GCM (cifra autenticada: detecta dado adulterado) com IV aleatório de 12 bytes por valor.
 *  - A chave mestra (32 bytes) vem de DATA_KEY ou DATA_KEY_FILE (AWS Secrets Manager / Docker secret).
 *    Dela saem duas subchaves independentes (HKDF-SHA256): uma para cifrar, outra para os índices.
 *  - O nome da coluna entra como dado autenticado (AAD): um valor copiado de uma coluna para outra não decifra.
 *  - Índice cego = HMAC-SHA256 do valor normalizado. Permite achar um CPF/e-mail exato e garantir
 *    unicidade sem guardar o CPF em texto. Sem a chave, o índice não pode ser refeito por força bruta.
 *
 * Formato guardado: enc:v1:<iv>.<tag>.<texto cifrado>   (base64url)
 */
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const PROD = process.env.NODE_ENV === 'production';
const PREFIXO = 'enc:v1:';

function carregaChaveMestra(dirDados) {
  let b64 = process.env.DATA_KEY;
  if (!b64 && process.env.DATA_KEY_FILE) b64 = fs.readFileSync(process.env.DATA_KEY_FILE, 'utf8').trim();
  delete process.env.DATA_KEY; // não deixa a chave no ambiente do processo depois de lida
  if (!b64) {
    if (PROD) throw new Error('Em produção é obrigatório definir DATA_KEY_FILE (ou DATA_KEY) com 32 bytes em base64.');
    // Desenvolvimento: gera uma chave local (arquivo 0600 dentro de data/, que o git ignora).
    const arq = path.join(dirDados, '.chave-dados');
    if (fs.existsSync(arq)) b64 = fs.readFileSync(arq, 'utf8').trim();
    else {
      b64 = crypto.randomBytes(32).toString('base64');
      fs.writeFileSync(arq, b64 + '\n', { mode: 0o600 });
      console.warn(`\n  Chave de criptografia de DESENVOLVIMENTO criada em ${arq}.`);
      console.warn('  Em produção use DATA_KEY_FILE. Sem esta chave os dados cifrados NÃO podem ser lidos: faça backup dela.\n');
    }
  }
  const mestra = Buffer.from(b64, 'base64');
  if (mestra.length !== 32) throw new Error('A chave de dados deve ter exatamente 32 bytes (base64). Gere com: openssl rand -base64 32');
  return mestra;
}

const dirDados = process.env.DATA_DIR || path.join(__dirname, 'data');
fs.mkdirSync(dirDados, { recursive: true });
const mestra = carregaChaveMestra(dirDados);
const subchave = (rotulo) => Buffer.from(crypto.hkdfSync('sha256', mestra, Buffer.alloc(0), rotulo, 32));
const kCifra = subchave('sorridonto/cifra/v1');
const kIndice = subchave('sorridonto/indice/v1');
mestra.fill(0); // a chave mestra não precisa ficar na memória: só as subchaves

const b64u = (b) => b.toString('base64url');

/** Cifra um texto. null/'' viram null. `coluna` identifica o campo (dado autenticado). */
function cifra(texto, coluna) {
  if (texto === null || texto === undefined || texto === '') return null;
  const iv = crypto.randomBytes(12);
  const c = crypto.createCipheriv('aes-256-gcm', kCifra, iv);
  c.setAAD(Buffer.from(coluna));
  const ct = Buffer.concat([c.update(String(texto), 'utf8'), c.final()]);
  return PREFIXO + [iv, c.getAuthTag(), ct].map(b64u).join('.');
}

/** Decifra. Valores antigos, sem o prefixo, são devolvidos como estão (migração). */
function decifra(valor, coluna) {
  if (valor === null || valor === undefined) return null;
  if (!String(valor).startsWith(PREFIXO)) return valor;
  const [iv, tag, ct] = String(valor).slice(PREFIXO.length).split('.').map((p) => Buffer.from(p, 'base64url'));
  try {
    const d = crypto.createDecipheriv('aes-256-gcm', kCifra, iv);
    d.setAAD(Buffer.from(coluna));
    d.setAuthTag(tag);
    return Buffer.concat([d.update(ct), d.final()]).toString('utf8');
  } catch {
    throw new Error(`Falha ao decifrar ${coluna}: chave incorreta ou dado adulterado.`);
  }
}

/** Índice cego determinístico para busca exata e unicidade. */
function indice(valor, coluna) {
  if (valor === null || valor === undefined || valor === '') return null;
  return crypto.createHmac('sha256', kIndice).update(coluna + '\0' + String(valor)).digest('base64url');
}

/** Cifra um arquivo inteiro (backup): 'SDB1' + iv(12) + tag(16) + dados cifrados. */
function cifraBuffer(buf) {
  const iv = crypto.randomBytes(12);
  const c = crypto.createCipheriv('aes-256-gcm', kCifra, iv);
  c.setAAD(Buffer.from('backup'));
  const ct = Buffer.concat([c.update(buf), c.final()]);
  return Buffer.concat([Buffer.from('SDB1'), iv, c.getAuthTag(), ct]);
}
function decifraBuffer(buf) {
  if (buf.subarray(0, 4).toString() !== 'SDB1') throw new Error('Arquivo de backup inválido.');
  const d = crypto.createDecipheriv('aes-256-gcm', kCifra, buf.subarray(4, 16));
  d.setAAD(Buffer.from('backup'));
  d.setAuthTag(buf.subarray(16, 32));
  try { return Buffer.concat([d.update(buf.subarray(32)), d.final()]); }
  catch { throw new Error('Não foi possível decifrar o backup: chave incorreta ou arquivo adulterado.'); }
}

const estaCifrado = (v) => typeof v === 'string' && v.startsWith(PREFIXO);

module.exports = { cifra, decifra, indice, estaCifrado, cifraBuffer, decifraBuffer, dirDados };
