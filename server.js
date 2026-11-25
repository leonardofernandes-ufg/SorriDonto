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
  const doUsuario = [...sessoes].filter(([, x]) => x.id === f.id_funcionario);
  if (doUsuario.length >= MAX_SESSOES_POR_USUARIO) sessoes.delete(doUsuario[0][0]);
  if (sessoes.size >= MAX_SESSOES) sessoes.delete(sessoes.keys().next().value);
  sessoes.set(sha(token), { id: f.id_funcionario, nome: f.nome, perfil: f.perfil, expira: Date.now() + SESSION_MS });
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

function dadosPaciente(b) {
  const nome = txt(b.nome, 120);
  const cpf = so(b.cpf);
  const telefone = so(b.telefone);
  const email = txt(b.email, 160).toLowerCase();
  const nasc = txt(b.data_nascimento, 10);
  if (nome.length < 3) throw new Erro(400, 'Informe o nome completo.');
  if (!cpfValido(cpf)) throw new Erro(400, 'CPF inválido.');
  if (telefone && !/^\d{10,11}$/.test(telefone)) throw new Erro(400, 'Telefone deve ter DDD e 8 ou 9 dígitos.');
  if (email && !emailValido(email)) throw new Erro(400, 'E-mail inválido.');
  if (nasc) {
    const dt = new Date(nasc + 'T00:00:00Z');
    if (!/^\d{4}-\d{2}-\d{2}$/.test(nasc) || isNaN(dt) || dt > new Date() || dt.getUTCFullYear() < 1900)
      throw new Erro(400, 'Data de nascimento inválida.');
  }
  return {
    nome, cpf, telefone: telefone || null, email: email || null, data_nascimento: nasc || null,
    cidade: txt(b.cidade, 80) || null, endereco: txt(b.endereco, 200) || null, observacoes: txt(b.observacoes, 1000) || null,
  };
}

const PERFIS = ['admin', 'dentista', 'recepcao'];
function dadosFuncionario(b, criando) {
  const nome = txt(b.nome, 120);
  const email = txt(b.email, 160).toLowerCase();
  const perfil = txt(b.perfil, 20);
  const telefone = so(b.telefone);
  const senha = String(b.senha ?? '');
  if (nome.length < 3) throw new Erro(400, 'Informe o nome completo.');
  if (!emailValido(email)) throw new Erro(400, 'E-mail inválido.');
  if (!PERFIS.includes(perfil)) throw new Erro(400, 'Perfil inválido.');
  if (telefone && !/^\d{10,11}$/.test(telefone)) throw new Erro(400, 'Telefone deve ter DDD e 8 ou 9 dígitos.');
  if (criando || senha) {
    if (senha.length < 8 || senha.length > 128) throw new Erro(400, 'A senha deve ter de 8 a 128 caracteres.');
  }
  return {
    nome, email, perfil, telefone: telefone || null, senha: senha || null,
    cargo: txt(b.cargo, 80) || null, cro: txt(b.cro, 20) || null,
  };
}

// ---------------------------------------------------------------- auditoria e permissões
function audita(idFuncionario, acao, detalhe) {
  db.prepare('INSERT INTO log_acesso (id_funcionario, acao, detalhe) VALUES (?, ?, ?)').run(idFuncionario ?? null, acao, detalhe ?? null);
}
function exige(sessao, ...perfis) {
  if (!sessao) throw new Erro(401, 'Faça login para continuar.');
  if (!perfis.includes(sessao.perfil)) throw new Erro(403, 'Seu perfil não tem permissão para esta ação.');
}
const mascaraCpf = (c) => `***.${c.slice(3, 6)}.***-**`;

// ---------------------------------------------------------------- primeiro administrador
// A senha inicial pode vir de ADMIN_PASSWORD_FILE (melhor: não fica em /proc/<pid>/environ) ou de
// ADMIN_PASSWORD. Em ambos os casos o valor é retirado de process.env depois de lido.
let senhaInicial = process.env.ADMIN_PASSWORD;
if (!senhaInicial && process.env.ADMIN_PASSWORD_FILE) senhaInicial = fs.readFileSync(process.env.ADMIN_PASSWORD_FILE, 'utf8').trim();
delete process.env.ADMIN_PASSWORD;
function semeiaAdmin() {
  if (db.prepare('SELECT COUNT(*) AS n FROM funcionario').get().n > 0) return;
  const email = (process.env.ADMIN_EMAIL || 'admin@sorridonto.local').toLowerCase();
  const gerada = !senhaInicial;
  const senha = senhaInicial || crypto.randomBytes(9).toString('base64url');
  db.prepare("INSERT INTO funcionario (nome, email, senha_hash, perfil, cargo) VALUES (?, ?, ?, 'admin', 'Administrador')")
    .run('Administrador', email, hashSenha(senha));
  console.log('\n  Primeiro acesso criado.');
  console.log(`  E-mail: ${email}`);
  console.log(gerada ? `  Senha:  ${senha}   (anote agora: não será exibida de novo)\n` : '  Senha:  definida por você (ADMIN_PASSWORD ou ADMIN_PASSWORD_FILE)\n');
}

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

const colunasPaciente = 'id_paciente, nome, cpf, data_nascimento, telefone, email, cidade, endereco, observacoes, criado_em';

async function api(req, res, url) {
  const { pathname } = url;
  const metodo = req.method;
  const s = sessaoDe(req);
  let m;

  // --- autenticação
  if (pathname === '/api/login' && metodo === 'POST') {
    const b = await lerJson(req);
    const email = txt(b.email, 160).toLowerCase();
    const ip = ipDe(req);
    const chave = `${ip}|${email}`;
    if (bloqueado(chave) || bloqueado('loginip|' + ip, 30)) throw new Erro(429, 'Muitas tentativas. Aguarde 15 minutos.');
    const f = db.prepare('SELECT * FROM funcionario WHERE email = ?').get(email);
    const ok = confereSenha(String(b.senha ?? ''), f ? f.senha_hash : HASH_FALSO) && f && f.ativo === 1;
    if (!ok) {
      falhou(chave);
      falhou('loginip|' + ip);
      audita(f?.id_funcionario, 'LOGIN_FALHOU', email);
      throw new Erro(401, 'E-mail ou senha incorretos.');
    }
    tentativas.delete(chave);
    audita(f.id_funcionario, 'LOGIN', null);
    res.setHeader('Set-Cookie', cookieSessao(criaSessao(f), SESSION_MS / 1000));
    return { id: f.id_funcionario, nome: f.nome, perfil: f.perfil };
  }
  if (pathname === '/api/logout' && metodo === 'POST') {
    if (s) { audita(s.id, 'LOGOUT', null); sessoes.delete(s.token); }
    res.setHeader('Set-Cookie', cookieSessao('', 0));
    return { ok: true };
  }
  if (pathname === '/api/me' && metodo === 'GET') {
    exige(s, ...PERFIS);
    return { id: s.id, nome: s.nome, perfil: s.perfil };
  }

  // --- interessados (formulário público da landing page)
  if (pathname === '/api/interesse' && metodo === 'POST') {
    const chave = `interesse|${ipDe(req)}`;
    if (bloqueado(chave, 5)) throw new Erro(429, 'Você já enviou alguns pedidos. Tente novamente mais tarde.');
    const b = await lerJson(req);
    const nome = txt(b.nome, 120);
    const email = txt(b.email, 160).toLowerCase();
    if (nome.length < 3) throw new Erro(400, 'Informe seu nome.');
    if (!emailValido(email)) throw new Erro(400, 'E-mail inválido.');
    const clinica = txt(b.clinica, 120) || null;     // valida tudo ANTES de contar a tentativa
    const mensagem = txt(b.mensagem, 500) || null;
    falhou(chave, 60 * 60 * 1000);
    db.prepare('INSERT INTO interesse (nome, email, clinica, mensagem) VALUES (?, ?, ?, ?)')
      .run(nome, cripto.cifra(email, 'interesse.email'), clinica, cripto.cifra(mensagem, 'interesse.mensagem'));
    return { ok: true };
  }
  if (pathname === '/api/interesse' && metodo === 'GET') {
    exige(s, 'admin');
    return db.prepare('SELECT id_interesse, nome, email, clinica, mensagem, criado_em FROM interesse ORDER BY id_interesse DESC LIMIT 200').all()
      .map((i) => ({ ...i, email: cripto.decifra(i.email, 'interesse.email'), mensagem: cripto.decifra(i.mensagem, 'interesse.mensagem') }));
  }

  // --- pacientes
  if (pathname === '/api/pacientes' && metodo === 'GET') {
    exige(s, 'admin', 'dentista', 'recepcao');
    const q = txt(url.searchParams.get('q'), 60);
    const like = `%${q.replace(/[%_\\]/g, '\\$&')}%`;
    // CPF e e-mail estão cifrados: a busca por eles é pelo valor COMPLETO, via índice cego (HMAC).
    const dig = so(q);
    const idxCpf = dig.length === 11 ? cripto.indice(dig, 'paciente.cpf') : null;
    const idxEmail = emailValido(q.toLowerCase()) ? cripto.indice(q.toLowerCase(), 'paciente.email') : null;
    const linhas = db.prepare(
      `SELECT ${colunasPaciente} FROM paciente
       WHERE nome LIKE ? ESCAPE '\\' OR cpf_idx = ? OR email_idx = ?
       ORDER BY nome COLLATE NOCASE LIMIT 500`
    ).all(like, idxCpf, idxEmail).map(db.doBanco);
    return linhas.map((p) => (s.perfil === 'admin' ? p : { ...p, cpf: mascaraCpf(p.cpf), observacoes: undefined }));
  }
  if (pathname === '/api/pacientes' && metodo === 'POST') {
    exige(s, 'admin', 'recepcao');
    const d = dadosPaciente(await lerJson(req));
    try {
      const c = db.paraBanco(d);
      const r = db.prepare(
        `INSERT INTO paciente (nome, cpf, cpf_idx, data_nascimento, telefone, email, email_idx, cidade, endereco, observacoes, criado_por)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
      ).run(d.nome, c.cpf, c.cpf_idx, c.data_nascimento, c.telefone, c.email, c.email_idx, d.cidade, c.endereco, c.observacoes, s.id);
      audita(s.id, 'PACIENTE_CRIADO', `id ${r.lastInsertRowid}`);
      return { id_paciente: Number(r.lastInsertRowid) };
    } catch (e) {
      if (/UNIQUE/.test(e.message)) throw new Erro(409, 'Já existe um paciente com este CPF.');
      throw e;
    }
  }
  if ((m = pathname.match(/^\/api\/pacientes\/(\d+)$/))) {
    const id = Number(m[1]);
    if (metodo === 'GET') {
      exige(s, 'admin', 'dentista', 'recepcao');
      const p = db.prepare(`SELECT ${colunasPaciente} FROM paciente WHERE id_paciente = ?`).get(id);
      if (!p) throw new Erro(404, 'Paciente não encontrado.');
      audita(s.id, 'PACIENTE_LIDO', `id ${id}`);
      return db.doBanco(p);
    }
    if (metodo === 'PUT') {
      exige(s, 'admin', 'recepcao');
      const d = dadosPaciente(await lerJson(req));
      try {
        const c = db.paraBanco(d);
        const r = db.prepare(
          `UPDATE paciente SET nome=?, cpf=?, cpf_idx=?, data_nascimento=?, telefone=?, email=?, email_idx=?, cidade=?, endereco=?, observacoes=?
           WHERE id_paciente = ?`
        ).run(d.nome, c.cpf, c.cpf_idx, c.data_nascimento, c.telefone, c.email, c.email_idx, d.cidade, c.endereco, c.observacoes, id);
        if (!r.changes) throw new Erro(404, 'Paciente não encontrado.');
      } catch (e) {
        if (/UNIQUE/.test(e.message)) throw new Erro(409, 'Já existe um paciente com este CPF.');
        throw e;
      }
      audita(s.id, 'PACIENTE_ALTERADO', `id ${id}`);
      return { ok: true };
    }
    if (metodo === 'DELETE') {
      exige(s, 'admin');
      const r = db.prepare('DELETE FROM paciente WHERE id_paciente = ?').run(id);
      if (!r.changes) throw new Erro(404, 'Paciente não encontrado.');
      audita(s.id, 'PACIENTE_EXCLUIDO', `id ${id}`);
      return { ok: true };
    }
  }

  // --- funcionários (somente administrador)
  const colunasFunc = 'id_funcionario, nome, email, perfil, cargo, cro, telefone, ativo, criado_em';
  if (pathname === '/api/funcionarios' && metodo === 'GET') {
    exige(s, 'admin');
    return db.prepare(`SELECT ${colunasFunc} FROM funcionario ORDER BY nome COLLATE NOCASE`).all();
  }
  if (pathname === '/api/funcionarios' && metodo === 'POST') {
    exige(s, 'admin');
    const d = dadosFuncionario(await lerJson(req), true);
    try {
      const r = db.prepare('INSERT INTO funcionario (nome, email, senha_hash, perfil, cargo, cro, telefone) VALUES (?, ?, ?, ?, ?, ?, ?)')
        .run(d.nome, d.email, hashSenha(d.senha), d.perfil, d.cargo, d.cro, d.telefone);
      audita(s.id, 'FUNCIONARIO_CRIADO', `id ${r.lastInsertRowid} (${d.perfil})`);
      return { id_funcionario: Number(r.lastInsertRowid) };
    } catch (e) {
      if (/UNIQUE/.test(e.message)) throw new Erro(409, 'Já existe um funcionário com este e-mail.');
      throw e;
    }
  }
  if ((m = pathname.match(/^\/api\/funcionarios\/(\d+)$/))) {
    const id = Number(m[1]);
    exige(s, 'admin');
    const atual = db.prepare('SELECT * FROM funcionario WHERE id_funcionario = ?').get(id);
    if (!atual) throw new Erro(404, 'Funcionário não encontrado.');
    if (metodo === 'GET') return db.prepare(`SELECT ${colunasFunc} FROM funcionario WHERE id_funcionario = ?`).get(id);
    if (metodo === 'PUT') {
      const b = await lerJson(req);
      const d = dadosFuncionario(b, false);
      const ativo = b.ativo === undefined ? atual.ativo : (b.ativo ? 1 : 0);
      const deixaDeSerAdminAtivo = atual.perfil === 'admin' && atual.ativo === 1 && (d.perfil !== 'admin' || ativo === 0);
      if (deixaDeSerAdminAtivo) {
        if (id === s.id) throw new Erro(400, 'Você não pode remover seu próprio acesso de administrador.');
        const outros = db.prepare("SELECT COUNT(*) AS n FROM funcionario WHERE perfil='admin' AND ativo=1 AND id_funcionario <> ?").get(id).n;
        if (!outros) throw new Erro(400, 'É preciso manter ao menos um administrador ativo.');
      }
      try {
        db.prepare('UPDATE funcionario SET nome=?, email=?, perfil=?, cargo=?, cro=?, telefone=?, ativo=? WHERE id_funcionario = ?')
          .run(d.nome, d.email, d.perfil, d.cargo, d.cro, d.telefone, ativo, id);
      } catch (e) {
        if (/UNIQUE/.test(e.message)) throw new Erro(409, 'Já existe um funcionário com este e-mail.');
        throw e;
      }
      if (d.senha) db.prepare('UPDATE funcionario SET senha_hash = ? WHERE id_funcionario = ?').run(hashSenha(d.senha), id);
      // encerra sessões abertas se o acesso foi desativado ou a senha trocada
      for (const [t, x] of sessoes) {
        if (x.id !== id) continue;
        if (!ativo || d.senha) sessoes.delete(t);
        else x.perfil = d.perfil;
      }
      audita(s.id, 'FUNCIONARIO_ALTERADO', `id ${id}${d.senha ? ' (senha redefinida)' : ''}`);
      return { ok: true };
    }
  }

  // --- auditoria
  if (pathname === '/api/auditoria' && metodo === 'GET') {
    exige(s, 'admin');
    return db.prepare(
      `SELECT l.id_log, l.momento, l.acao, l.detalhe, f.nome AS funcionario
       FROM log_acesso l LEFT JOIN funcionario f USING (id_funcionario)
       ORDER BY l.id_log DESC LIMIT 200`
    ).all();
  }

  throw new Erro(404, 'Rota não encontrada.');
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
      const corpo = await api(req, res, url);
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

const migrados = db.migraCriptografia();
if (migrados) console.log(`  Criptografia: ${migrados} registro(s) antigos foram cifrados e o arquivo do banco foi reescrito.`);
semeiaAdmin();
servidor.listen(PORT, HOST, () => console.log(`SorriDonto em http://${HOST}:${PORT}  (área administrativa: /admin)`));
