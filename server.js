'use strict';
const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const db = require('./db');
const cripto = require('./cripto');

const PORT = Number(process.env.PORT) || 3000;
const HOST = process.env.HOST || '127.0.0.1';
const PROD = process.env.NODE_ENV === 'production';
const PUBLIC = path.join(__dirname, 'public');
const SESSION_MS = 8 * 60 * 60 * 1000;

// ---------------------------------------------------------------- senhas
function hashSenha(senha) {
  const salt = crypto.randomBytes(16);
  const hash = crypto.scryptSync(senha, salt, 64);
  return `${salt.toString('hex')}:${hash.toString('hex')}`;
}
function confereSenha(senha, armazenada) {
  const [saltHex, hashHex] = String(armazenada).split(':');
  const esperado = Buffer.from(hashHex || '', 'hex');
  const obtido = crypto.scryptSync(senha, Buffer.from(saltHex || '', 'hex'), 64);
  return esperado.length === obtido.length && crypto.timingSafeEqual(esperado, obtido);
}
const HASH_FALSO = hashSenha(crypto.randomBytes(8).toString('hex')); // iguala o tempo de login com e-mail inexistente

// ---------------------------------------------------------------- sessões
const sessoes = new Map(); // sha256(token) -> { id, nome, perfil, expira }
const MAX_SESSOES = 2000;
const MAX_SESSOES_POR_USUARIO = 5;
const sha = (t) => crypto.createHash('sha256').update(t).digest('base64url');
function criaSessao(f) {
  const token = crypto.randomBytes(32).toString('base64url');
  // Só o HASH do token fica na memória do servidor: um despejo de memória não revela cookies válidos.
  const doUsuario = [...sessoes].filter(([, x]) => x.id === f.id_usuario);
  if (doUsuario.length >= MAX_SESSOES_POR_USUARIO) sessoes.delete(doUsuario[0][0]);
  if (sessoes.size >= MAX_SESSOES) sessoes.delete(sessoes.keys().next().value);
  sessoes.set(sha(token), { id: f.id_usuario, nome: f.nome, perfil: f.perfil, empresa: f.id_empresa, expira: Date.now() + SESSION_MS });
  return token;
}
function lerCookie(req, nome) {
  const m = (req.headers.cookie || '').split(';').map((s) => s.trim()).find((s) => s.startsWith(nome + '='));
  return m ? m.slice(nome.length + 1) : null;
}
function sessaoDe(req) {
  const cookie = lerCookie(req, 'sid');
  if (!cookie || cookie.length > 64) return null;
  const token = sha(cookie);
  const s = sessoes.get(token);
  if (!s) return null;
  if (s.expira < Date.now()) { sessoes.delete(token); return null; }
  return { ...s, token };
}
/** Encerra as sessões de uma pessoa (bloqueio, troca de senha) ou só a sessão `soEsta` (logout). */
function encerraSessoesDe(id, soEsta) {
  if (soEsta) { sessoes.delete(soEsta); return; }
  for (const [t, x] of sessoes) if (x.id === id) sessoes.delete(t);
}
const limpaTentativas = (chave) => tentativas.delete(chave);
function cookieSessao(token, maxAge) {
  return `sid=${token}; HttpOnly; SameSite=Strict; Path=/; Max-Age=${maxAge}${PROD ? '; Secure' : ''}`;
}
setInterval(() => {
  const agora = Date.now();
  for (const [t, s] of sessoes) if (s.expira < agora) sessoes.delete(t);
  for (const [k, v] of tentativas) if (v.reinicia < agora) tentativas.delete(k);
}, 10 * 60 * 1000).unref();

// ---------------------------------------------------------------- limite de tentativas de login
const tentativas = new Map(); // ip|email -> { n, reinicia }
const MAX_TENTATIVAS = 8;
function bloqueado(chave, max = MAX_TENTATIVAS) {
  const t = tentativas.get(chave);
  return !!t && t.reinicia > Date.now() && t.n >= max;
}
function falhou(chave, janela = 15 * 60 * 1000) {
  const t = tentativas.get(chave);
  if (!t || t.reinicia < Date.now()) tentativas.set(chave, { n: 1, reinicia: Date.now() + janela });
  else t.n++;
}

// Limite geral de requisições por IP (janela de 1 min). Protege a aplicação de inundação simples;
// um DDoS de verdade precisa também de proxy/CDN/WAF na frente (ver README).
const LIMITE_POR_MIN = Number(process.env.RATE_LIMIT_PER_MIN) || 240;
const MAX_CHAVES = 50000;   // teto de memória do contador
const CONFIA_PROXY = process.env.TRUST_PROXY === '1';
function ipDe(req) {
  if (CONFIA_PROXY) {
    const ultimo = String(req.headers['x-forwarded-for'] || '').split(',').pop().trim();
    if (ultimo) return ultimo.slice(0, 64);
  }
  return req.socket.remoteAddress || '?';
}
function limiteGeral(req, res) {
  const chave = 'rl|' + ipDe(req);
  const agora = Date.now();
  let t = tentativas.get(chave);
  if (!t || t.reinicia < agora) {
    if (tentativas.size >= MAX_CHAVES) for (const k of [...tentativas.keys()].slice(0, MAX_CHAVES / 10)) tentativas.delete(k);
    tentativas.set(chave, { n: 1, reinicia: agora + 60 * 1000 });
    return;
  }
  if (++t.n > LIMITE_POR_MIN) {
    res.setHeader('Retry-After', String(Math.ceil((t.reinicia - agora) / 1000)));
    throw new Erro(429, 'Muitas requisições. Tente novamente em instantes.');
  }
}

// ---------------------------------------------------------------- validação
class Erro extends Error {
  constructor(status, msg) { super(msg); this.status = status; }
}
const so = (v) => String(v ?? '').replace(/\D/g, '');
const CONTROLE = /[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F]/g;
const MARCACAO_HTML = /<\s*\/?\s*[a-zA-Z!?]/;
const txt = (v, max) => {
  const t = String(v ?? '').replace(CONTROLE, '').trim().slice(0, max);
  if (MARCACAO_HTML.test(t)) throw new Erro(400, 'Não é permitido código HTML nos campos de texto.');
  return t;
};

function cpfValido(c) {
  if (!/^\d{11}$/.test(c) || /^(\d)\1{10}$/.test(c)) return false;
  for (let t = 9; t < 11; t++) {
    let s = 0;
    for (let i = 0; i < t; i++) s += Number(c[i]) * (t + 1 - i);
    if (((s * 10) % 11) % 10 !== Number(c[t])) return false;
  }
  return true;
}
const emailValido = (e) => /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(e) && e.length <= 160;

const mascaraCpf = (c) => `***.${c.slice(3, 6)}.***-**`;

// ---------------------------------------------------------------- API
async function lerJson(req) {
  if (!(req.headers['content-type'] || '').startsWith('application/json')) throw new Erro(415, 'Envie JSON.');
  const LIMITE = 64 * 1024;
  if (Number(req.headers['content-length']) > LIMITE) { req.resume(); throw new Erro(413, 'Requisição grande demais.'); }
  const partes = [];
  let total = 0;
  for await (const p of req) {
    total += p.length;
    if (total > LIMITE) { req.destroy(); throw new Erro(413, 'Requisição grande demais.'); }
    partes.push(p);
  }
  const texto = Buffer.concat(partes).toString('utf8') || '{}';
  // Poluição de protótipo / injeção em objetos: nenhum campo com esses nomes é aceito.
  if (/"(__proto__|constructor|prototype)"\s*:/.test(texto)) throw new Erro(400, 'Campo não permitido.');
  let obj;
  try { obj = JSON.parse(texto); } catch { throw new Erro(400, 'JSON inválido.'); }
  if (obj === null || typeof obj !== 'object' || Array.isArray(obj)) throw new Erro(400, 'Envie um objeto JSON.');
  if (['__proto__', 'constructor', 'prototype'].some((k) => Object.prototype.hasOwnProperty.call(obj, k))) throw new Erro(400, 'Campo não permitido.');
  return obj;
}

const API = require('./api')({
  db, cripto, Erro, txt, so, cpfValido, emailValido, mascaraCpf, lerJson, sessaoDe, criaSessao, cookieSessao,
  encerraSessoesDe, hashSenha, confereSenha, HASH_FALSO, bloqueado, falhou, limpaTentativas, ipDe, SESSION_MS,
});

// ---------------------------------------------------------------- primeiro administrador e dados de demonstração
// A senha inicial pode vir de ADMIN_PASSWORD_FILE (melhor: não fica em /proc/<pid>/environ) ou de
// ADMIN_PASSWORD. Em ambos os casos o valor é retirado de process.env depois de lido.
let senhaInicial = process.env.ADMIN_PASSWORD;
if (!senhaInicial && process.env.ADMIN_PASSWORD_FILE) senhaInicial = fs.readFileSync(process.env.ADMIN_PASSWORD_FILE, 'utf8').trim();
delete process.env.ADMIN_PASSWORD;

function semeia() {
  if (db.prepare('SELECT COUNT(*) AS n FROM usuario').get().n > 0) return;
  const email = (process.env.ADMIN_EMAIL || 'admin@aegislock.local').toLowerCase();
  const demo = process.env.SEED_DEMO !== '0';           // SEED_DEMO=0 cria só o administrador
  const gerada = !senhaInicial;
  const nova = () => crypto.randomBytes(9).toString('base64url');
  const senhaAdmin = senhaInicial || nova();
  const dia = API.hoje();
  const mais = (n) => new Date(Date.now() + n * 86400000).toLocaleDateString('sv-SE', { timeZone: 'America/Sao_Paulo' });
  const senhasDemo = [];

  db.exec('BEGIN');
  const emp = Number(db.prepare('INSERT INTO empresa (nome) VALUES (?)').run(process.env.EMPRESA_NOME || 'Residencial Jardim das Acácias').lastInsertRowid);
  const pessoa = (nome, unidade, mail, perfil, situacao = 'ATIVO') =>
    Number(db.prepare('INSERT INTO usuario (nome, unidade, situacao, id_empresa, email, perfil) VALUES (?, ?, ?, ?, ?, ?)').run(nome, unidade, situacao, emp, mail, perfil).lastInsertRowid);
  const cred = (idu, tipo, senha) => {
    const id = Number(db.prepare('INSERT INTO credencial (id_usuario, senha, tipo) VALUES (?, ?, ?)').run(idu, hashSenha(senha), tipo).lastInsertRowid);
    db.prepare(tipo === 'C' ? 'INSERT INTO cracha (id_credencial) VALUES (?)' : 'INSERT INTO cartao (id_credencial) VALUES (?)').run(id);
    return id;
  };
  const local = (nome, criticidade, tipo) => {
    const id = Number(db.prepare('INSERT INTO recurso (id_empresa, nome, criticidade, tipo) VALUES (?, ?, ?, ?)').run(emp, nome, criticidade, tipo).lastInsertRowid);
    db.prepare(tipo === 'F' ? 'INSERT INTO recurso_fisico (id_recurso) VALUES (?)' : 'INSERT INTO recurso_logico (id_recurso) VALUES (?)').run(id);
    return id;
  };
  const libera = (idu, idr, inicio, fim = null) =>
    db.prepare("INSERT INTO autorizacao (id_usuario, id_recurso, inicio, fim, situacao) VALUES (?, ?, ?, ?, 'ATIVA')").run(idu, idr, inicio, fim);

  const admin = pessoa('Administrador', 'Administração', email, 'ADMIN');
  cred(admin, 'T', senhaAdmin);
  const crAdmin = cred(admin, 'C', nova());
  let demoCasos = [];
  if (demo) {
    const portaria = local('Portaria principal', 'ALTA', 'F');
    const garagem = local('Portão da garagem', 'MEDIA', 'F');
    const cameras = local('Sala de câmeras', 'ALTA', 'F');
    local('Sistema de controle de acesso', 'ALTA', 'L');
    local('Sistema de câmeras (CFTV)', 'ALTA', 'L');
    const paulo = pessoa('Paulo Porteiro', 'Portaria', 'paulo@aegislock.local', 'PORTEIRO');
    const ana = pessoa('Ana Moradora', 'Apto 101', 'ana@aegislock.local', 'MORADOR');
    const carlos = pessoa('Carlos Morador', 'Apto 202', 'carlos@aegislock.local', 'MORADOR');
    const davi = pessoa('Davi Morador', 'Apto 303', 'davi@aegislock.local', 'MORADOR', 'BLOQUEADO');
    const sp = nova(); const sa = nova();
    cred(paulo, 'T', sp); cred(ana, 'T', sa);
    senhasDemo.push(['Paulo Porteiro (porteiro)', 'paulo@aegislock.local', sp], ['Ana Moradora (moradora)', 'ana@aegislock.local', sa]);
    const cPaulo = cred(paulo, 'C', nova()); const cAna = cred(ana, 'C', nova());
    const cCarlos = cred(carlos, 'C', nova()); const cDavi = cred(davi, 'C', nova());
    for (const r of [portaria, garagem, cameras]) libera(admin, r, '2026-01-01');
    libera(paulo, portaria, '2026-01-01'); libera(paulo, cameras, '2026-01-01');
    libera(ana, portaria, '2026-01-01'); libera(ana, garagem, '2026-01-01');
    libera(carlos, portaria, '2026-01-01'); libera(carlos, garagem, '2025-01-01', '2026-01-31');   // vencida
    libera(davi, portaria, '2026-01-01');
    const visitante = (nome, cpf, tel) => {
      const c = db.cifraVisitante({ cpf, telefone: tel });
      return Number(db.prepare('INSERT INTO visitante (id_empresa, nome, cpf, cpf_idx, telefone) VALUES (?, ?, ?, ?, ?)').run(emp, nome, c.cpf, c.cpf_idx, c.telefone).lastInsertRowid);
    };
    const v1 = visitante('Bruno Teixeira', '52998224725', '62977776666');
    const v2 = visitante('Julia Martins', '11144477735', '62991112233');
    db.prepare("INSERT INTO visita (id_empresa, id_visitante, id_anfitriao, id_recurso, data_prevista, status) VALUES (?, ?, ?, ?, ?, 'AUTORIZADA')").run(emp, v1, ana, portaria, `${dia}T15:00`);
    db.prepare("INSERT INTO visita (id_empresa, id_visitante, id_anfitriao, id_recurso, data_prevista, status) VALUES (?, ?, ?, ?, ?, 'AGENDADA')").run(emp, v2, carlos, portaria, `${mais(1)}T16:30`);
    demoCasos = [[cAna, portaria], [cAna, garagem], [cAna, cameras], [cCarlos, portaria], [cCarlos, garagem], [cDavi, portaria],
      [cPaulo, portaria], [cPaulo, cameras], [999999, portaria], [crAdmin, cameras], [cAna, portaria], [cCarlos, portaria]];
  }
  db.exec('COMMIT');
  for (const [c, r] of demoCasos) API.decidirAcesso(emp, c, r);   // passagens de exemplo, decididas pela mesma regra da portaria

  console.log('\n  Primeiro acesso criado.');
  console.log(`  Administrador: ${email}`);
  console.log(gerada ? `  Senha:         ${senhaAdmin}   (anote agora: não será exibida de novo)` : '  Senha:         definida por você (ADMIN_PASSWORD ou ADMIN_PASSWORD_FILE)');
  if (demo) {
    console.log('  Dados de demonstração criados (condomínio fictício). Contas de teste:');
    for (const [quem, mail, sen] of senhasDemo) console.log(`    ${quem}: ${mail}  senha ${sen}`);
  }
  console.log('');
}

// ---------------------------------------------------------------- arquivos estáticos
const TIPOS = {
  '.html': 'text/html; charset=utf-8', '.css': 'text/css; charset=utf-8', '.js': 'text/javascript; charset=utf-8',
  '.svg': 'image/svg+xml', '.png': 'image/png', '.jpg': 'image/jpeg', '.ico': 'image/x-icon', '.webp': 'image/webp',
};
const PAGINAS = { '/': 'index.html', '/admin': 'admin.html' };

function estatico(req, res, pathname) {
  if (req.method !== 'GET' && req.method !== 'HEAD') throw new Erro(405, 'Método não permitido.');
  let rel;
  try { rel = PAGINAS[pathname] || decodeURIComponent(pathname).replace(/^\/+/, ''); }
  catch { throw new Erro(400, 'Endereço inválido.'); }
  if (rel.includes('\0') || rel.split(/[\\/]/).some((p) => p.startsWith('.'))) throw new Erro(404, 'Página não encontrada.');
  const arquivo = path.normalize(path.join(PUBLIC, rel));
  if (!arquivo.startsWith(PUBLIC + path.sep)) throw new Erro(403, 'Acesso negado.');
  let stat;
  try { stat = fs.statSync(arquivo); } catch { throw new Erro(404, 'Página não encontrada.'); }
  if (!stat.isFile()) throw new Erro(404, 'Página não encontrada.');
  res.writeHead(200, {
    'Content-Type': TIPOS[path.extname(arquivo)] || 'application/octet-stream',
    'Content-Length': stat.size,
    'Cache-Control': 'no-cache',
  });
  if (req.method === 'HEAD') return res.end();
  fs.createReadStream(arquivo).pipe(res);
}

// ---------------------------------------------------------------- servidor
const CABECALHOS = {
  ...(PROD ? { 'Strict-Transport-Security': 'max-age=63072000; includeSubDomains' } : {}),
  'Content-Security-Policy': "default-src 'self'; img-src 'self' data:; style-src 'self'; script-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'",
  'X-Content-Type-Options': 'nosniff',
  'X-Frame-Options': 'DENY',
  'Referrer-Policy': 'same-origin',
  'Permissions-Policy': 'geolocation=(), camera=(), microphone=()',
};

const servidor = http.createServer({ maxHeaderSize: 16 * 1024, connectionsCheckingInterval: 2000 }, async (req, res) => {
  for (const [k, v] of Object.entries(CABECALHOS)) res.setHeader(k, v);
  let url;
  try { url = new URL(req.url, 'http://localhost'); }
  catch {
    res.writeHead(400, { 'Content-Type': 'text/plain; charset=utf-8' });
    return res.end('Endereço inválido.');
  }
  try {
    limiteGeral(req, res);
    if (url.pathname.startsWith('/api/')) {
      res.setHeader('Cache-Control', 'no-store');
      const corpo = await API.handler(req, res, url);
      res.writeHead(200, { 'Content-Type': 'application/json; charset=utf-8' });
      res.end(JSON.stringify(corpo));
    } else {
      estatico(req, res, url.pathname);
    }
  } catch (e) {
    const status = e instanceof Erro ? e.status : 500;
    if (status === 500) console.error(e);
    if (res.headersSent) return res.end();
    const json = url.pathname.startsWith('/api/');
    res.writeHead(status, { 'Content-Type': json ? 'application/json; charset=utf-8' : 'text/plain; charset=utf-8' });
    const msg = status === 500 ? 'Erro interno.' : e.message;
    res.end(json ? JSON.stringify({ erro: msg }) : msg);
  }
});

// Anti-DDoS lento (slowloris) e esgotamento de conexões
servidor.headersTimeout = 10_000;
servidor.requestTimeout = 15_000;
servidor.keepAliveTimeout = 5_000;
servidor.maxRequestsPerSocket = 500;
servidor.maxHeadersCount = 60;
servidor.maxConnections = Number(process.env.MAX_CONNECTIONS) || 500;
// Conexão que não completa uma requisição em 12 s é derrubada: cobre conexões ociosas que nunca
// enviam nada e o slowloris (cabeçalho enviado a conta-gotas). Os timers nativos do Node não
// cobrem esse caso quando há muitas conexões ociosas abertas.
servidor.on('connection', (socket) => {
  const limite = setTimeout(() => { if (!socket.pedidoCompleto) socket.destroy(); }, 12_000);
  socket.once('close', () => clearTimeout(limite));
});
servidor.on('request', (req) => { req.socket.pedidoCompleto = true; });
servidor.on('clientError', (err, socket) => {
  if (socket.writable) socket.end('HTTP/1.1 400 Bad Request\r\nConnection: close\r\n\r\n');
  else socket.destroy();
});
process.on('unhandledRejection', (e) => console.error('Promessa rejeitada:', e));

semeia();
servidor.listen(PORT, HOST, () => console.log(`AegisLock em http://${HOST}:${PORT}  (área administrativa: /admin)`));
