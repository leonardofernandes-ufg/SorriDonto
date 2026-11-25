'use strict';
/**
 * Verificação de segurança do SorriDonto: simula os ataques mais comuns contra o sistema
 * em execução e informa APROVADO / FALHOU / ALERTA para cada um.
 *
 * Use SÓ contra o seu próprio sistema (ambiente local ou de teste).
 *
 *   TEST_EMAIL=admin@sorridonto.local TEST_SENHA='...' node security/verifica.js
 *
 * Variáveis opcionais:
 *   BASE_URL            (padrão http://127.0.0.1:3000)
 *   RATE_LIMIT_PER_MIN  (o mesmo valor usado pelo servidor; padrão 240)
 *   SERVER_PID          (PID do servidor, para os testes de memória; se omitido, tenta achar)
 *   PULAR_DDOS=1        (pula inundação e slowloris, que levam ~1 minuto)
 *
 * Sai com código 1 se algum teste FALHAR. Gera security/relatorio.md.
 */
const fs = require('fs');
const net = require('net');
const path = require('path');
const crypto = require('crypto');
const { execFileSync } = require('child_process');

const BASE = process.env.BASE_URL || 'http://127.0.0.1:3000';
const U = new URL(BASE);
const EMAIL = process.env.TEST_EMAIL;
const SENHA = process.env.TEST_SENHA;
const LIMITE = Number(process.env.RATE_LIMIT_PER_MIN) || 240;
const PUBLIC = path.join(__dirname, '..', 'public');

const resultados = [];
let secao = '';
let requisicoes = 0;
let cookie = '';

const titulo = (t) => { secao = t; console.log(`\n== ${t}`); };
function registra(nivel, nome, detalhe = '') {
  resultados.push({ secao, nivel, nome, detalhe });
  const marca = { APROVADO: '✔', FALHOU: '✘', ALERTA: '!', PULADO: '-' }[nivel];
  console.log(`  ${marca} ${nivel.padEnd(8)} ${nome}${detalhe ? '  → ' + detalhe : ''}`);
}
const ok = (cond, nome, detalhe, nivelSeFalhar = 'FALHOU') => registra(cond ? 'APROVADO' : nivelSeFalhar, nome, detalhe);
const dorme = (ms) => new Promise((r) => setTimeout(r, ms));

// Respeita o limite do servidor: espera a janela de 1 minuto se estiver perto do teto.
async function req(caminho, opcoes = {}) {
  if (!opcoes.semLimite && ++requisicoes > LIMITE * 0.7) {
    console.log('    (aguardando a janela do limite de requisições reiniciar…)');
    await dorme(61000);
    requisicoes = 1;
  }
  const headers = { ...(opcoes.headers || {}) };
  if (opcoes.auth && cookie) headers.cookie = cookie;
  let body = opcoes.corpoBruto;
  if (opcoes.json !== undefined) { headers['content-type'] = 'application/json'; body = JSON.stringify(opcoes.json); }
  const t0 = Date.now();
  try {
    const r = await fetch(BASE + caminho, { method: opcoes.metodo || 'GET', headers, body, redirect: 'manual', signal: AbortSignal.timeout(opcoes.timeout || 15000) });
    const texto = await r.text();
    return { status: r.status, headers: r.headers, texto, ms: Date.now() - t0 };
  } catch (e) {
    return { status: 0, erro: e.message, texto: '', headers: new Headers(), ms: Date.now() - t0 };
  }
}

// Requisição crua por socket (para URLs e cabeçalhos que o fetch normalizaria ou recusaria).
function bruto(dados, esperaMs = 1500) {
  return new Promise((resolve) => {
    const s = net.connect(Number(U.port) || 80, U.hostname);
    let out = '';
    const fim = () => { s.destroy(); resolve(out); };
    s.setTimeout(esperaMs, fim);
    s.on('data', (d) => { out += d.toString('latin1'); });
    s.on('error', fim);
    s.on('close', () => resolve(out));
    s.on('connect', () => s.write(dados));
  });
}
const statusBruto = (r) => { const m = r.match(/^HTTP\/1\.[01] (\d{3})/); return m ? Number(m[1]) : 0; };
const vivo = async () => (await req('/', { semLimite: true })).status === 200;

function cpfAleatorio() {
  const d = Array.from({ length: 9 }, () => Math.floor(Math.random() * 10));
  for (let t = 9; t < 11; t++) {
    let s = 0;
    for (let i = 0; i < t; i++) s += d[i] * (t + 1 - i);
    d.push(((s * 10) % 11) % 10);
  }
  return d.join('');
}

// ------------------------------------------------------------------ 1. cabeçalhos
async function cabecalhos() {
  titulo('1. Cabeçalhos HTTP e cookies');
  const r = await req('/');
  const csp = r.headers.get('content-security-policy') || '';
  ok(/script-src 'self'/.test(csp) && !/unsafe-inline|unsafe-eval/.test(csp), 'CSP bloqueia script inline e eval', csp.slice(0, 60) + '…');
  ok(/frame-ancestors 'none'/.test(csp) && r.headers.get('x-frame-options') === 'DENY', 'Proteção contra clickjacking (frame-ancestors / X-Frame-Options)');
  ok(r.headers.get('x-content-type-options') === 'nosniff', 'X-Content-Type-Options: nosniff');
  ok(!r.headers.get('x-powered-by'), 'Não revela a tecnologia do servidor (X-Powered-By)');
  const a = await req('/api/me');
  ok((a.headers.get('cache-control') || '').includes('no-store'), 'Respostas da API não ficam em cache');
  ok((a.headers.get('content-type') || '').startsWith('application/json'), 'API responde com content-type JSON');
  const t = await bruto('TRACE / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n');
  ok(statusBruto(t) === 405, 'Método TRACE recusado', 'status ' + statusBruto(t));

  if (!EMAIL || !SENHA) return registra('PULADO', 'Login de teste', 'defina TEST_EMAIL e TEST_SENHA para os testes autenticados');
  const l = await req('/api/login', { metodo: 'POST', json: { email: EMAIL, senha: SENHA } });
  if (l.status !== 200) return registra('FALHOU', 'Login de teste', 'status ' + l.status + ' (confira TEST_EMAIL/TEST_SENHA)');
  const sc = l.headers.get('set-cookie') || '';
  cookie = sc.split(';')[0];
  ok(/HttpOnly/i.test(sc), 'Cookie de sessão é HttpOnly (JavaScript não lê)');
  ok(/SameSite=Strict/i.test(sc), 'Cookie de sessão é SameSite=Strict (protege contra CSRF)');
  ok(/Secure/i.test(sc), 'Cookie de sessão é Secure', 'só ativa com NODE_ENV=production atrás de HTTPS', 'ALERTA');
}

// ------------------------------------------------------------------ 2. SQL injection
async function sqli() {
  titulo('2. SQL injection');
  const cargas = ["' OR '1'='1", "admin@x.com' --", "' OR 1=1 --", '" OR ""="', "'; DROP TABLE funcionario;--",
    "' UNION SELECT 1,2,3,4,5,6,7,8,9--"];
  let semAcesso = true;
  for (const c of cargas) {
    for (const campo of ['email', 'senha']) {
      const corpo = { email: 'x@x.com', senha: 'x' };
      corpo[campo] = c;
      const r = await req('/api/login', { metodo: 'POST', json: corpo });
      if (r.status === 200 || (r.headers.get('set-cookie') || '').includes('sid=')) semAcesso = false;
    }
  }
  ok(semAcesso, `Login resiste a ${cargas.length * 2} cargas de SQL injection (e-mail e senha)`);

  if (!cookie) return registra('PULADO', 'Testes de SQL injection autenticados', 'sem login de teste');
  const base = await req('/api/pacientes?q=' + encodeURIComponent('zzz-nao-existe-' + crypto.randomBytes(4).toString('hex')), { auth: true });
  const nBase = JSON.parse(base.texto || '[]').length;
  const busca = ["' OR '1'='1", "%", "_", "' UNION SELECT senha_hash,email,1,1,1,1,1,1,1,1 FROM funcionario--",
    "'; DROP TABLE paciente;--", "1' AND (SELECT COUNT(*) FROM funcionario)>0--", "\\' OR 1=1--"];
  let literal = true, vazou = false;
  for (const c of busca) {
    const r = await req('/api/pacientes?q=' + encodeURIComponent(c), { auth: true });
    if (r.status !== 200) { literal = false; continue; }
    if (/senha_hash|[0-9a-f]{32}:[0-9a-f]{128}/.test(r.texto)) vazou = true;
    if (JSON.parse(r.texto).length > nBase) literal = false;
  }
  ok(literal, `Busca trata ${busca.length} cargas como texto comum (nenhuma linha a mais que o normal)`);
  ok(!vazou, 'Nenhum hash de senha aparece nas respostas');
  const t0 = Date.now();
  await req('/api/pacientes?q=' + encodeURIComponent("1' AND (SELECT randomblob(400000000))--"), { auth: true });
  ok(Date.now() - t0 < 3000, 'Injeção por tempo (randomblob) não atrasa a resposta', (Date.now() - t0) + ' ms');
  const ids = ['1%20OR%201=1', '1;DROP%20TABLE%20paciente', '1%27--', '-1%20UNION%20SELECT%201'];
  let nenhum = true;
  for (const i of ids) { const r = await req('/api/pacientes/' + i, { auth: true }); if (![404, 400].includes(r.status)) nenhum = false; }
  ok(nenhum, 'ID na URL só aceita números (outros valores dão 404)');

  // grava um texto malicioso (sem tags) e confere que fica literal e que as tabelas seguem íntegras
  const nome = "Robert'); DROP TABLE paciente;--";
  const cpf = cpfAleatorio();
  const c = await req('/api/pacientes', { metodo: 'POST', auth: true, json: { nome, cpf } });
  ok(c.status === 200, 'Cadastro aceita aspas e ponto e vírgula como texto', 'status ' + c.status);
  if (c.status === 200) {
    const id = JSON.parse(c.texto).id_paciente;
    const g = await req('/api/pacientes/' + id, { auth: true });
    ok(JSON.parse(g.texto).nome === nome, 'O texto foi gravado literalmente, sem executar');
    const l = await req('/api/pacientes', { auth: true });
    const f = await req('/api/funcionarios', { auth: true });
    ok(l.status === 200 && f.status === 200, 'Tabelas paciente e funcionario continuam existindo');
    await req('/api/pacientes/' + id, { metodo: 'DELETE', auth: true });
  }
}

// ------------------------------------------------------------------ 3. HTML injection / XSS
async function xss() {
  titulo('3. Injeção de HTML / XSS');
  const cargas = ['<script>alert(1)</script>', '<img src=x onerror=alert(1)>', '"><svg/onload=alert(1)>',
    '<iframe src=javascript:alert(1)>', '<a href="javascript:alert(1)">x</a>', '< script >alert(1)</ script >', '<!--', '<?xml'];
  let publico = 0, auth = 0;
  for (const c of cargas) {
    const r = await req('/api/interesse', { metodo: 'POST', json: { nome: 'Teste Segurança', email: 'seg@exemplo.com', mensagem: c } });
    if (r.status === 400) publico++;
    if (cookie) {
      const a = await req('/api/pacientes', { metodo: 'POST', auth: true, json: { nome: 'Teste ' + c, cpf: cpfAleatorio() } });
      const b = await req('/api/pacientes', { metodo: 'POST', auth: true, json: { nome: 'Teste Seguro', cpf: cpfAleatorio(), observacoes: c } });
      if (a.status === 400 && b.status === 400) auth++;
      else for (const x of [a, b]) if (x.status === 200) await req('/api/pacientes/' + JSON.parse(x.texto).id_paciente, { metodo: 'DELETE', auth: true });
    }
  }
  ok(publico === cargas.length, `Formulário público recusa ${cargas.length} cargas de HTML`, `${publico}/${cargas.length}`);
  if (cookie) ok(auth === cargas.length, `Cadastro de paciente recusa HTML em nome e observações`, `${auth}/${cargas.length}`);
  const f = await req('/api/funcionarios', { metodo: 'POST', auth: true, json: { nome: '<b>x</b>', email: 'xss@teste.local', perfil: 'recepcao', senha: 'senha-segura-1' } });
  if (cookie) ok(f.status === 400, 'Cadastro de funcionário recusa HTML', 'status ' + f.status);
  const ref = await req('/%3Cscript%3Ealert(1)%3C/script%3E');
  ok(!ref.texto.includes('<script') && (ref.headers.get('content-type') || '').startsWith('text/plain'), 'Páginas de erro não refletem o que foi digitado na URL');

  // análise estática do front-end: nada que interprete texto como HTML ou código
  const arquivos = fs.readdirSync(PUBLIC).filter((a) => /\.(js|html)$/.test(a));
  const perigos = [];
  for (const a of arquivos) {
    const t = fs.readFileSync(path.join(PUBLIC, a), 'utf8');
    const regras = [[/\.innerHTML\s*=|\.outerHTML\s*=|insertAdjacentHTML|document\.write\(/, 'insere HTML'], [/\beval\s*\(|new Function\s*\(/, 'executa texto como código'],
      [/\son[a-z]+\s*=\s*["']/i, 'manipulador inline (onclick=…)'], [/href\s*=\s*["']javascript:/i, 'link javascript:']];
    for (const [re, msg] of regras) if (re.test(t)) perigos.push(`${a}: ${msg}`);
    if (a.endsWith('.html') && /<script(?![^>]*\bsrc=)[^>]*>/i.test(t)) perigos.push(`${a}: script inline`);
  }
  ok(perigos.length === 0, `Front-end sem pontos perigosos (${arquivos.length} arquivos analisados)`, perigos.join('; '));
}

// ------------------------------------------------------------------ 4. injeção em memória / dados malformados
async function injecao() {
  titulo('4. Injeção em memória: protótipo, corpos gigantes, JSON malicioso e URLs malformadas');
  const proto = ['{"__proto__":{"admin":true},"email":"a@b.com","senha":"x"}', '{"constructor":{"prototype":{"x":1}},"email":"a@b.com","senha":"x"}',
    '{"\\u005f\\u005fproto\\u005f\\u005f":{"admin":true},"email":"a@b.com","senha":"x"}'];
  let rec = 0;
  for (const p of proto) {
    const r = await req('/api/login', { metodo: 'POST', headers: { 'content-type': 'application/json' }, corpoBruto: p });
    if (r.status === 400) rec++;
  }
  ok(rec === proto.length, 'Poluição de protótipo (__proto__, constructor) é recusada', `${rec}/${proto.length}`);

  const fundo = await req('/api/login', { metodo: 'POST', headers: { 'content-type': 'application/json' }, corpoBruto: '['.repeat(60000) });
  ok([400, 413].includes(fundo.status) && await vivo(), 'JSON com 60.000 níveis de aninhamento não derruba o servidor', 'status ' + fundo.status);
  const grande = await req('/api/login', { metodo: 'POST', headers: { 'content-type': 'application/json' }, corpoBruto: JSON.stringify({ email: 'a'.repeat(70000) }) });
  ok(grande.status === 413, 'Corpo de 70 KB é recusado (limite de 64 KB)', 'status ' + grande.status);
  const mentira = await bruto(`POST /api/login HTTP/1.1\r\nHost: x\r\nContent-Type: application/json\r\nContent-Length: 99999999999\r\nConnection: close\r\n\r\n{}`);
  ok([400, 413].includes(statusBruto(mentira)) || statusBruto(mentira) === 0, 'Content-Length absurdo é recusado sem ler o corpo', 'status ' + statusBruto(mentira));
  const binario = await req('/api/login', { metodo: 'POST', headers: { 'content-type': 'application/json' }, corpoBruto: Buffer.from([0xff, 0xfe, 0x00, 0x80, 0x7b]) });
  ok(binario.status === 400, 'Corpo binário/UTF-8 inválido dá 400', 'status ' + binario.status);
  const cab = await bruto(`GET / HTTP/1.1\r\nHost: x\r\nCookie: ${'a'.repeat(20000)}\r\nConnection: close\r\n\r\n`);
  ok([400, 431].includes(statusBruto(cab)) || statusBruto(cab) === 0, 'Cabeçalho de 20 KB é recusado', 'status ' + statusBruto(cab));

  const malformadas = ['GET http://[ HTTP/1.1', 'GET //[::1 HTTP/1.1', 'GET /%E0%A4%A HTTP/1.1', 'GET /%00 HTTP/1.1', 'GET /\u0000 HTTP/1.1', 'GET /' + 'A'.repeat(9000) + ' HTTP/1.1'];
  let semCrash = true;
  for (const m of malformadas) { await bruto(`${m}\r\nHost: x\r\nConnection: close\r\n\r\n`); if (!await vivo()) semCrash = false; }
  ok(semCrash, `Servidor sobrevive a ${malformadas.length} URLs malformadas`);

  const trav = ['GET /../server.js HTTP/1.1', 'GET /../../etc/passwd HTTP/1.1', 'GET /%2e%2e/server.js HTTP/1.1', 'GET /..%2fdb.js HTTP/1.1',
    'GET /%2e%2e%2f%2e%2e%2fetc%2fpasswd HTTP/1.1', 'GET /public/../data/sorridonto.db HTTP/1.1', 'GET /..%00/server.js HTTP/1.1',
    'GET /.env HTTP/1.1', 'GET /.git/config HTTP/1.1', 'GET /data/sorridonto.db HTTP/1.1', 'GET /package.json HTTP/1.1'];
  let seguro = true; const vazados = [];
  for (const t of trav) {
    const r = await bruto(`${t}\r\nHost: x\r\nConnection: close\r\n\r\n`);
    const corpo = r.split('\r\n\r\n').slice(1).join('');
    if (statusBruto(r) === 200 || /require\(|root:|SQLite format|DatabaseSync/.test(corpo)) { seguro = false; vazados.push(t.split(' ')[1]); }
  }
  ok(seguro, `Path traversal e arquivos sensíveis: ${trav.length} tentativas bloqueadas`, vazados.join(', '));
  const m = await Promise.all(['PUT', 'DELETE', 'PATCH'].map((x) => req('/', { metodo: x })));
  ok(m.every((r) => r.status === 405), 'Métodos PUT/DELETE/PATCH em páginas estáticas recusados');
}

// ------------------------------------------------------------------ 5. memória do processo
async function memoria() {
  titulo('5. Memory finder: leitura da memória do processo do servidor (Linux)');
  if (process.platform !== 'linux') return registra('PULADO', 'Testes de memória', 'só em Linux');
  let pid = Number(process.env.SERVER_PID);
  if (!pid) {
    try { pid = Number(execFileSync('pgrep', ['-f', 'node.*server\\.js'], { encoding: 'utf8' }).trim().split('\n')[0]); } catch { /* sem pgrep */ }
  }
  if (!pid) return registra('PULADO', 'Testes de memória', 'PID do servidor não encontrado (use SERVER_PID)');
  console.log(`    servidor: PID ${pid}`);

  let escopo = '?';
  try { escopo = fs.readFileSync('/proc/sys/kernel/yama/ptrace_scope', 'utf8').trim(); } catch { /* sem Yama */ }
  ok(escopo !== '0' && escopo !== '?', 'ptrace_scope (Yama) restringe a leitura da memória por outros processos', 'valor ' + escopo + (escopo === '0' ? ': qualquer processo do mesmo usuário pode ler a memória do servidor (ver README)' : ''), 'ALERTA');

  try {
    const env = fs.readFileSync(`/proc/${pid}/environ`, 'latin1');
    ok(!/ADMIN_PASSWORD=/.test(env), 'Senha inicial não está no ambiente do processo (/proc/PID/environ)', 'use ADMIN_PASSWORD_FILE', 'ALERTA');
  } catch { registra('APROVADO', 'Ambiente do processo (/proc/PID/environ) não é legível por este usuário'); }

  if (!SENHA || !cookie) return registra('PULADO', 'Busca de segredos na memória', 'sem login de teste');
  const sid = cookie.replace(/^sid=/, '');
  const alvos = { 'senha em texto': [Buffer.from(SENHA), Buffer.from(SENHA, 'utf16le')], 'cookie de sessão (token cru)': [Buffer.from(sid)] };
  let fd;
  try { fd = fs.openSync(`/proc/${pid}/mem`, 'r'); }
  catch (e) { return registra('APROVADO', 'Memória do servidor NÃO pôde ser lida por este processo', e.code); }
  const achados = { 'senha em texto': 0, 'cookie de sessão (token cru)': 0 };
  let lidos = 0;
  try {
    const mapas = fs.readFileSync(`/proc/${pid}/maps`, 'utf8').split('\n');
    for (const l of mapas) {
      const m = l.match(/^([0-9a-f]+)-([0-9a-f]+) rw-p/);
      if (!m || /\[(vvar|vsyscall)|\.so|\.dll/.test(l)) continue;
      let ini = BigInt('0x' + m[1]); const fim = BigInt('0x' + m[2]);
      while (ini < fim) {
        const n = Number(fim - ini > 4194304n ? 4194304n : fim - ini);
        const buf = Buffer.alloc(n);
        let r = 0;
        try { r = fs.readSync(fd, buf, 0, n, ini); } catch { break; }
        if (!r) break;
        lidos += r;
        for (const [nome, vars] of Object.entries(alvos)) for (const v of vars) if (buf.subarray(0, r).includes(v)) achados[nome]++;
        ini += BigInt(n);
      }
    }
  } finally { fs.closeSync(fd); }
  console.log(`    ${(lidos / 1048576).toFixed(0)} MB de memória lidos`);
  for (const [nome, n] of Object.entries(achados)) {
    if (n === 0) registra('APROVADO', `${nome} não encontrado(a) na memória do servidor`);
    else registra('ALERTA', `${nome} encontrado(a) na memória do servidor (${n} ocorrência/s)`, 'resíduo da requisição até o coletor de lixo; mitigue com ptrace_scope ≥ 1, usuário dedicado e contêiner');
  }
}

// ------------------------------------------------------------------ 6. força bruta e negação de serviço
async function ddos() {
  titulo('6. Força bruta e negação de serviço (DoS/DDoS na camada da aplicação)');
  const falso = `forca-bruta-${crypto.randomBytes(3).toString('hex')}@teste.local`;
  let primeiro429 = 0;
  for (let i = 1; i <= 12; i++) {
    const r = await req('/api/login', { metodo: 'POST', json: { email: falso, senha: 'errada' + i } });
    if (r.status === 429 && !primeiro429) primeiro429 = i;
  }
  ok(primeiro429 > 0 && primeiro429 <= 9, 'Força bruta no login é bloqueada (429)', primeiro429 ? `bloqueio na tentativa ${primeiro429}` : 'nunca bloqueou');

  if (process.env.PULAR_DDOS === '1') return registra('PULADO', 'Inundação, conexões ociosas e slowloris', 'PULAR_DDOS=1');

  // conexões ociosas em massa: o servidor deve continuar atendendo
  const ociosas = [];
  for (let i = 0; i < 150; i++) { const s = net.connect(Number(U.port) || 80, U.hostname); s.on('error', () => {}); s.resume(); ociosas.push(s); }
  await dorme(500);
  const r = await req('/', { semLimite: true });
  ok(r.status === 200, 'Atende normalmente com 150 conexões ociosas abertas', 'status ' + r.status + ', ' + r.ms + ' ms');

  // slowloris: cabeçalho incompleto que nunca termina
  const t0 = Date.now();
  const lento = await new Promise((resolve) => {
    const s = net.connect(Number(U.port) || 80, U.hostname);
    s.resume();
    s.on('connect', () => { s.write('GET / HTTP/1.1\r\nHost: x\r\nX-Lento: a\r\n'); });
    s.on('close', () => resolve(Date.now() - t0));
    s.on('error', () => resolve(Date.now() - t0));
    setTimeout(() => { s.destroy(); resolve(-1); }, 20000);
  });
  ok(lento > 0 && lento < 16000, 'Slowloris (cabeçalho que nunca termina) é cortado pelo servidor', lento > 0 ? `conexão encerrada em ${(lento / 1000).toFixed(1)} s` : 'não foi cortado em 20 s');
  await dorme(1000);
  const fechadas = ociosas.filter((s) => s.destroyed).length;
  ok(fechadas === ociosas.length, 'Conexões ociosas que nunca enviam nada são fechadas pelo servidor', `${fechadas}/${ociosas.length} fechadas`);
  ociosas.forEach((s) => s.destroy());

  // inundação de requisições de um mesmo IP
  const total = LIMITE + 160;
  const estatus = {}; let maior429 = 0; let feitas = 0;
  const lote = async () => {
    while (feitas < total) {
      feitas++;
      const x = await req('/api/me', { semLimite: true });
      estatus[x.status] = (estatus[x.status] || 0) + 1;
      if (x.status === 429) maior429 = Math.max(maior429, x.ms);
    }
  };
  const ini = Date.now();
  await Promise.all(Array.from({ length: 40 }, lote));
  console.log(`    ${total} requisições em ${((Date.now() - ini) / 1000).toFixed(1)} s: ` + JSON.stringify(estatus));
  ok((estatus[429] || 0) > 0, 'Inundação de requisições é limitada (429 após o teto por minuto)', `${estatus[429] || 0} bloqueadas de ${total}`);
  ok(maior429 < 1000, 'As respostas 429 são rápidas (o servidor não gasta trabalho com o excesso)', maior429 + ' ms no pior caso');
  let voltou = 0;
  for (let i = 0; i < 70; i++) { if ((await req('/', { semLimite: true })).status === 200) { voltou = i; break; } await dorme(1000); voltou = -1; }
  ok(voltou >= 0, 'Servidor volta ao normal depois da inundação', voltou >= 0 ? `após ${voltou} s` : 'não voltou em 70 s');
  requisicoes = 0;
}

// ------------------------------------------------------------------ relatório
function relatorio() {
  const cont = (n) => resultados.filter((r) => r.nivel === n).length;
  console.log(`\n== Resumo: ${cont('APROVADO')} aprovados, ${cont('FALHOU')} falharam, ${cont('ALERTA')} alertas, ${cont('PULADO')} pulados`);
  const linhas = [`# Relatório de verificação de segurança – SorriDonto`, '', `Executado em ${new Date().toLocaleString('pt-BR')} contra \`${BASE}\`.`, '',
    `**${cont('APROVADO')} aprovados · ${cont('FALHOU')} falharam · ${cont('ALERTA')} alertas · ${cont('PULADO')} pulados**`, ''];
  let atual = '';
  for (const r of resultados) {
    if (r.secao !== atual) { atual = r.secao; linhas.push('', `## ${atual}`, '', '| Resultado | Verificação | Detalhe |', '|---|---|---|'); }
    linhas.push(`| ${r.nivel} | ${r.nome} | ${(r.detalhe || '').replace(/\|/g, '\\|')} |`);
  }
  linhas.push('', '> Limites conhecidos: a verificação cobre a camada da aplicação. Um DDoS volumétrico (rede) só se resolve com CDN/WAF/proxy na frente; a leitura de memória por outro processo do mesmo usuário depende do sistema operacional (ptrace_scope), pois o JavaScript não consegue apagar com garantia strings já criadas.');
  fs.writeFileSync(path.join(__dirname, 'relatorio.md'), linhas.join('\n') + '\n');
  if (cont('FALHOU') > 0) process.exitCode = 1;
}

(async () => {
  console.log(`Verificação de segurança em ${BASE}`);
  if (!(await vivo())) { console.error('Servidor não responde em ' + BASE); process.exit(2); }
  await cabecalhos();
  await sqli();
  await xss();
  await injecao();
  await memoria();
  await ddos();
  relatorio();
})();
