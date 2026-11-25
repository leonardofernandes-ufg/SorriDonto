'use strict';
/**
 * API do AegisLock (portaria e controle de acesso).
 *
 * Perfis (usuario.perfil) e o que cada um pode:
 *   ADMIN     tudo da própria empresa: pessoas, credenciais, locais, autorizações (liberação), visitas,
 *             visitantes, acessos, auditoria e interessados.
 *   PORTEIRO  portaria (decidir e registrar passagem), visitas (autorizar/negar/realizar), visitantes,
 *             acessos; vê pessoas, locais e autorizações só para consulta.
 *   MORADOR   só o que é dele: suas visitas (agendar/cancelar), seus acessos e suas autorizações.
 * Toda consulta é filtrada pela empresa da sessão (isolamento entre clientes).
 */
module.exports = function criaApi(ctx) {
  const {
    db, cripto, Erro, txt, so, cpfValido, emailValido, mascaraCpf, lerJson, sessaoDe, criaSessao, cookieSessao,
    encerraSessoesDe, hashSenha, confereSenha, HASH_FALSO, bloqueado, falhou, limpaTentativas, ipDe, SESSION_MS,
  } = ctx;

  const PERFIS = ['ADMIN', 'PORTEIRO', 'MORADOR'];
  const SITUACOES = ['ATIVO', 'INATIVO', 'BLOQUEADO'];
  const hoje = () => new Date().toLocaleDateString('sv-SE', { timeZone: 'America/Sao_Paulo' });
  const dataOk = (v) => /^\d{4}-\d{2}-\d{2}$/.test(v) && !isNaN(new Date(v + 'T00:00:00Z'));
  const dataHoraOk = (v) => /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}$/.test(v) && !isNaN(new Date(v + ':00Z'));
  const likeDe = (q) => `%${q.replace(/[%_\\]/g, '\\$&')}%`;

  function exige(s, ...perfis) {
    if (!s) throw new Erro(401, 'Faça login para continuar.');
    if (!perfis.includes(s.perfil)) throw new Erro(403, 'Seu perfil não tem permissão para esta ação.');
  }
  function audita(s, acao, detalhe) {
    db.prepare('INSERT INTO log_auditoria (id_usuario, id_empresa, acao, detalhe) VALUES (?, ?, ?, ?)')
      .run(s?.id ?? null, s?.empresa ?? null, acao, detalhe ?? null);
  }
  function transacao(fn) {
    db.exec('BEGIN');
    try { const r = fn(); db.exec('COMMIT'); return r; } catch (e) { db.exec('ROLLBACK'); throw e; }
  }
  const unico = (e, msg) => { if (/UNIQUE/.test(e.message)) throw new Erro(409, msg); throw e; };
  const emUso = (e, msg) => { if (/FOREIGN KEY/.test(e.message)) throw new Erro(409, msg); throw e; };

  // ------------------------------------------------------------------ validações
  function dadosUsuario(b) {
    const nome = txt(b.nome, 120);
    const unidade = txt(b.unidade, 80);
    const email = txt(b.email, 160).toLowerCase();
    const perfil = txt(b.perfil, 10).toUpperCase();
    const situacao = txt(b.situacao || 'ATIVO', 10).toUpperCase();
    const senha = String(b.senha ?? '');
    if (nome.length < 3) throw new Erro(400, 'Informe o nome completo.');
    if (!unidade) throw new Erro(400, 'Informe a unidade (apartamento, sala ou setor).');
    if (!emailValido(email)) throw new Erro(400, 'E-mail inválido.');
    if (!PERFIS.includes(perfil)) throw new Erro(400, 'Perfil inválido.');
    if (!SITUACOES.includes(situacao)) throw new Erro(400, 'Situação inválida.');
    if (senha && (senha.length < 8 || senha.length > 128)) throw new Erro(400, 'A senha deve ter de 8 a 128 caracteres.');
    return { nome, unidade, email, perfil, situacao, senha: senha || null };
  }
  function dadosVisitante(b) {
    const nome = txt(b.nome, 120);
    const cpf = so(b.cpf);
    const telefone = so(b.telefone);
    if (nome.length < 3) throw new Erro(400, 'Informe o nome completo do visitante.');
    if (!cpfValido(cpf)) throw new Erro(400, 'CPF do visitante inválido.');
    if (telefone && !/^\d{10,11}$/.test(telefone)) throw new Erro(400, 'Telefone deve ter DDD e 8 ou 9 dígitos.');
    return { nome, cpf, telefone: telefone || null };
  }
  function acharOuCriaVisitante(empresa, d) {
    const idx = cripto.indice(d.cpf, 'visitante.cpf');
    const ex = db.prepare('SELECT id_visitante FROM visitante WHERE id_empresa = ? AND cpf_idx = ?').get(empresa, idx);
    if (ex) return ex.id_visitante;
    const c = db.cifraVisitante(d);
    const r = db.prepare('INSERT INTO visitante (id_empresa, nome, cpf, cpf_idx, telefone) VALUES (?, ?, ?, ?, ?)')
      .run(empresa, d.nome, c.cpf, c.cpf_idx, c.telefone);
    return Number(r.lastInsertRowid);
  }
  const usuarioDaEmpresa = (id, empresa) =>
    db.prepare('SELECT * FROM usuario WHERE id_usuario = ? AND id_empresa = ?').get(id, empresa);
  const recursoDaEmpresa = (id, empresa) =>
    db.prepare('SELECT * FROM recurso WHERE id_recurso = ? AND id_empresa = ?').get(id, empresa);
  const inteiro = (v, msg) => { const n = Number(v); if (!Number.isInteger(n) || n < 0) throw new Erro(400, msg); return n; };

  // ------------------------------------------------------------------ a decisão da catraca
  /** Confere usuário ativo + autorização vigente e GRAVA a tentativa (permitida ou negada, com motivo). */
  function decidirAcesso(empresa, idCredencial, idRecurso) {
    const r = recursoDaEmpresa(idRecurso, empresa);
    if (!r) throw new Erro(404, 'Local não encontrado.');
    if (r.tipo !== 'F') throw new Erro(400, 'A portaria só decide acesso a locais físicos.');
    const c = db.prepare(
      `SELECT c.id_credencial, u.id_usuario, u.nome, u.unidade, u.situacao
       FROM credencial c JOIN usuario u ON u.id_usuario = c.id_usuario
       WHERE c.id_credencial = ? AND c.tipo = 'C' AND u.id_empresa = ?`).get(idCredencial, empresa);
    let motivo = null;
    if (!c) motivo = 'credencial desconhecida';
    else if (c.situacao !== 'ATIVO') motivo = `usuário ${c.situacao.toLowerCase()}`;
    else {
      const a = db.prepare('SELECT * FROM autorizacao WHERE id_usuario = ? AND id_recurso = ?').get(c.id_usuario, idRecurso);
      const dia = hoje();
      if (!a) motivo = 'sem autorização neste local';
      else if (a.situacao !== 'ATIVA') motivo = 'autorização suspensa';
      else if (a.inicio > dia) motivo = 'autorização ainda não iniciada';
      else if (a.fim && a.fim < dia) motivo = 'autorização vencida';
    }
    const resultado = motivo ? 'NEGADO' : 'PERMITIDO';
    const t = db.prepare('INSERT INTO tentativa (id_usuario, id_recurso, resultado, motivo_recusa) VALUES (?, ?, ?, ?)')
      .run(c ? c.id_usuario : null, idRecurso, resultado, motivo);
    return { id_tentativa: Number(t.lastInsertRowid), resultado, motivo, pessoa: c ? c.nome : null, unidade: c ? c.unidade : null, local: r.nome };
  }

  /** Situação "efetiva" de uma autorização, para mostrar na tela. */
  function vigencia(a, dia) {
    if (a.situacao !== 'ATIVA') return 'SUSPENSA';
    if (a.inicio > dia) return 'FUTURA';
    if (a.fim && a.fim < dia) return 'VENCIDA';
    return 'VIGENTE';
  }

  // ------------------------------------------------------------------ roteador
  async function handler(req, res, url) {
    const { pathname } = url;
    const metodo = req.method;
    const s = sessaoDe(req);
    let m;

    // ---- autenticação ----
    if (pathname === '/api/login' && metodo === 'POST') {
      const b = await lerJson(req);
      const email = txt(b.email, 160).toLowerCase();
      const ip = ipDe(req);
      const chave = `${ip}|${email}`;
      if (bloqueado(chave) || bloqueado('loginip|' + ip, 30)) throw new Erro(429, 'Muitas tentativas. Aguarde 15 minutos.');
      const u = db.prepare('SELECT * FROM usuario WHERE email = ?').get(email);
      // o painel usa a credencial do tipo T (cartão = acesso lógico) como senha de login
      const creds = u ? db.prepare("SELECT senha FROM credencial WHERE id_usuario = ? AND tipo = 'T'").all(u.id_usuario) : [];
      let ok = false;
      if (creds.length) for (const c of creds) ok = confereSenha(String(b.senha ?? ''), c.senha) || ok;
      else confereSenha(String(b.senha ?? ''), HASH_FALSO);   // mesmo tempo de resposta com e-mail inexistente
      ok = ok && u.situacao === 'ATIVO';
      if (!ok) {
        falhou(chave);
        falhou('loginip|' + ip);
        audita(u ? { id: u.id_usuario, empresa: u.id_empresa } : null, 'LOGIN_FALHOU', email);
        throw new Erro(401, 'E-mail ou senha incorretos, ou usuário sem acesso.');
      }
      limpaTentativas(chave);
      const sess = { id: u.id_usuario, empresa: u.id_empresa };
      audita(sess, 'LOGIN', null);
      res.setHeader('Set-Cookie', cookieSessao(criaSessao({ id_usuario: u.id_usuario, nome: u.nome, perfil: u.perfil, id_empresa: u.id_empresa }), SESSION_MS / 1000));
      return { id: u.id_usuario, nome: u.nome, perfil: u.perfil };
    }
    if (pathname === '/api/logout' && metodo === 'POST') {
      if (s) { audita(s, 'LOGOUT', null); encerraSessoesDe(s.id, s.token); }
      res.setHeader('Set-Cookie', cookieSessao('', 0));
      return { ok: true };
    }
    if (pathname === '/api/me' && metodo === 'GET') {
      exige(s, ...PERFIS);
      const e = db.prepare('SELECT nome FROM empresa WHERE id_empresa = ?').get(s.empresa);
      const u = db.prepare('SELECT unidade FROM usuario WHERE id_usuario = ?').get(s.id);
      return { id: s.id, nome: s.nome, perfil: s.perfil, empresa: e?.nome ?? '', unidade: u?.unidade ?? '' };
    }

    // ---- formulário público da landing ----
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
      exige(s, 'ADMIN');
      return db.prepare('SELECT id_interesse, nome, email, clinica, mensagem, criado_em FROM interesse ORDER BY id_interesse DESC LIMIT 200').all()
        .map((i) => ({ ...i, email: cripto.decifra(i.email, 'interesse.email'), mensagem: cripto.decifra(i.mensagem, 'interesse.mensagem') }));
    }

    // ---- visão geral ----
    if (pathname === '/api/resumo' && metodo === 'GET') {
      exige(s, 'ADMIN', 'PORTEIRO');
      const e = s.empresa;
      const dia = hoje();
      const por = db.prepare(
        `SELECT t.resultado AS r, COUNT(*) AS n FROM tentativa t JOIN recurso r ON r.id_recurso = t.id_recurso
         WHERE r.id_empresa = ? AND date(t.data_hora, '-3 hours') = ? GROUP BY t.resultado`).all(e, dia);
      const n = (r) => por.find((x) => x.r === r)?.n ?? 0;
      const conta = (sql, ...p) => db.prepare(sql).get(...p).n;
      return {
        permitidas: n('PERMITIDO'),
        negadas: n('NEGADO'),
        visitasHoje: conta("SELECT COUNT(*) AS n FROM visita WHERE id_empresa = ? AND substr(data_prevista, 1, 10) = ? AND status IN ('AGENDADA','AUTORIZADA')", e, dia),
        pessoasAtivas: conta("SELECT COUNT(*) AS n FROM usuario WHERE id_empresa = ? AND situacao = 'ATIVO'", e),
        bloqueadas: conta("SELECT COUNT(*) AS n FROM usuario WHERE id_empresa = ? AND situacao <> 'ATIVO'", e),
        locais: conta("SELECT COUNT(*) AS n FROM recurso WHERE id_empresa = ? AND tipo = 'F'", e),
        autorizacoes: conta(
          `SELECT COUNT(*) AS n FROM autorizacao a JOIN usuario u ON u.id_usuario = a.id_usuario
           WHERE u.id_empresa = ? AND a.situacao = 'ATIVA' AND a.inicio <= ? AND (a.fim IS NULL OR a.fim >= ?)`, e, dia, dia),
      };
    }

    // ---- pessoas (usuario) ----
    if (pathname === '/api/usuarios' && metodo === 'GET') {
      exige(s, 'ADMIN', 'PORTEIRO');
      const q = txt(url.searchParams.get('q'), 60);
      const like = likeDe(q);
      if (s.perfil === 'ADMIN') {
        return db.prepare(
          `SELECT u.id_usuario, u.nome, u.unidade, u.situacao, u.email, u.perfil,
                  (SELECT COUNT(*) FROM credencial c WHERE c.id_usuario = u.id_usuario) AS credenciais
           FROM usuario u WHERE u.id_empresa = ?
             AND (u.nome LIKE ? ESCAPE '\\' OR u.unidade LIKE ? ESCAPE '\\' OR u.email LIKE ? ESCAPE '\\')
           ORDER BY u.nome COLLATE NOCASE LIMIT 500`).all(s.empresa, like, like, like);
      }
      return db.prepare(
        `SELECT id_usuario, nome, unidade, situacao, perfil FROM usuario
         WHERE id_empresa = ? AND (nome LIKE ? ESCAPE '\\' OR unidade LIKE ? ESCAPE '\\')
         ORDER BY nome COLLATE NOCASE LIMIT 500`).all(s.empresa, like, like);
    }
    if (pathname === '/api/usuarios' && metodo === 'POST') {
      exige(s, 'ADMIN');
      const d = dadosUsuario(await lerJson(req));
      try {
        const id = transacao(() => {
          const r = db.prepare('INSERT INTO usuario (nome, unidade, situacao, id_empresa, email, perfil) VALUES (?, ?, ?, ?, ?, ?)')
            .run(d.nome, d.unidade, d.situacao, s.empresa, d.email, d.perfil);
          const novo = Number(r.lastInsertRowid);
          if (d.senha) {
            const c = db.prepare("INSERT INTO credencial (id_usuario, senha, tipo) VALUES (?, ?, 'T')").run(novo, hashSenha(d.senha));
            db.prepare('INSERT INTO cartao (id_credencial) VALUES (?)').run(Number(c.lastInsertRowid));
          }
          return novo;
        });
        audita(s, 'USUARIO_CRIADO', `id ${id} (${d.perfil})${d.senha ? ' com cartão de acesso ao painel' : ''}`);
        return { id_usuario: id };
      } catch (e) { return unico(e, 'Já existe uma pessoa com este e-mail.'); }
    }
    if ((m = pathname.match(/^\/api\/usuarios\/(\d+)$/))) {
      exige(s, 'ADMIN');
      const id = Number(m[1]);
      const atual = usuarioDaEmpresa(id, s.empresa);
      if (!atual) throw new Erro(404, 'Pessoa não encontrada.');
      if (metodo === 'GET') {
        const { id_usuario, nome, unidade, situacao, email, perfil } = atual;
        return { id_usuario, nome, unidade, situacao, email, perfil };
      }
      if (metodo === 'PUT') {
        const d = dadosUsuario(await lerJson(req));
        const perdeAdmin = atual.perfil === 'ADMIN' && atual.situacao === 'ATIVO' && (d.perfil !== 'ADMIN' || d.situacao !== 'ATIVO');
        if (perdeAdmin) {
          if (id === s.id) throw new Erro(400, 'Você não pode bloquear nem rebaixar o seu próprio acesso.');
          const outros = db.prepare("SELECT COUNT(*) AS n FROM usuario WHERE id_empresa = ? AND perfil = 'ADMIN' AND situacao = 'ATIVO' AND id_usuario <> ?").get(s.empresa, id).n;
          if (!outros) throw new Erro(400, 'É preciso manter ao menos um administrador ativo.');
        }
        try {
          db.prepare('UPDATE usuario SET nome = ?, unidade = ?, situacao = ?, email = ?, perfil = ? WHERE id_usuario = ?')
            .run(d.nome, d.unidade, d.situacao, d.email, d.perfil, id);
        } catch (e) { return unico(e, 'Já existe uma pessoa com este e-mail.'); }
        if (d.situacao !== 'ATIVO' || d.perfil !== atual.perfil) encerraSessoesDe(id);   // o bloqueio vale na hora
        const mudou = [atual.situacao !== d.situacao && `situação ${atual.situacao}→${d.situacao}`, atual.perfil !== d.perfil && `perfil ${atual.perfil}→${d.perfil}`].filter(Boolean).join(', ');
        audita(s, 'USUARIO_ALTERADO', `id ${id}${mudou ? ' | ' + mudou : ''}`);
        return { ok: true };
      }
    }

    // ---- credenciais (crachá e cartão) ----
    if (pathname === '/api/credenciais' && metodo === 'GET') {
      exige(s, 'ADMIN');
      return db.prepare(
        `SELECT c.id_credencial, c.id_usuario, u.nome, u.unidade, u.situacao, c.tipo
         FROM credencial c JOIN usuario u ON u.id_usuario = c.id_usuario WHERE u.id_empresa = ?
         ORDER BY u.nome COLLATE NOCASE, c.tipo`).all(s.empresa);
    }
    if (pathname === '/api/credenciais' && metodo === 'POST') {
      exige(s, 'ADMIN');
      const b = await lerJson(req);
      const idu = inteiro(b.id_usuario, 'Escolha a pessoa.');
      const tipo = txt(b.tipo, 1).toUpperCase();
      const senha = String(b.senha ?? '');
      if (!['C', 'T'].includes(tipo)) throw new Erro(400, 'Tipo de credencial inválido.');
      if (!usuarioDaEmpresa(idu, s.empresa)) throw new Erro(404, 'Pessoa não encontrada.');
      if (senha.length < 8 || senha.length > 128) throw new Erro(400, 'O código/senha deve ter de 8 a 128 caracteres.');
      const id = transacao(() => {
        const c = db.prepare('INSERT INTO credencial (id_usuario, senha, tipo) VALUES (?, ?, ?)').run(idu, hashSenha(senha), tipo);
        const novo = Number(c.lastInsertRowid);
        db.prepare(tipo === 'C' ? 'INSERT INTO cracha (id_credencial) VALUES (?)' : 'INSERT INTO cartao (id_credencial) VALUES (?)').run(novo);
        return novo;
      });
      audita(s, 'CREDENCIAL_EMITIDA', `id ${id} (${tipo === 'C' ? 'crachá' : 'cartão'}) para usuario ${idu}`);
      return { id_credencial: id };
    }
    if ((m = pathname.match(/^\/api\/credenciais\/(\d+)$/))) {
      exige(s, 'ADMIN');
      const id = Number(m[1]);
      const c = db.prepare(
        `SELECT c.* FROM credencial c JOIN usuario u ON u.id_usuario = c.id_usuario WHERE c.id_credencial = ? AND u.id_empresa = ?`).get(id, s.empresa);
      if (!c) throw new Erro(404, 'Credencial não encontrada.');
      if (metodo === 'PUT') {
        const senha = String((await lerJson(req)).senha ?? '');
        if (senha.length < 8 || senha.length > 128) throw new Erro(400, 'O código/senha deve ter de 8 a 128 caracteres.');
        db.prepare('UPDATE credencial SET senha = ? WHERE id_credencial = ?').run(hashSenha(senha), id);
        if (c.tipo === 'T') encerraSessoesDe(c.id_usuario);
        audita(s, 'CREDENCIAL_SENHA_REDEFINIDA', `id ${id}`);
        return { ok: true };
      }
      if (metodo === 'DELETE') {
        db.prepare('DELETE FROM credencial WHERE id_credencial = ?').run(id);
        if (c.tipo === 'T') encerraSessoesDe(c.id_usuario);
        audita(s, 'CREDENCIAL_REVOGADA', `id ${id} (${c.tipo === 'C' ? 'crachá' : 'cartão'}) de usuario ${c.id_usuario}`);
        return { ok: true };
      }
    }

    // ---- locais e sistemas (recurso) ----
    if (pathname === '/api/recursos' && metodo === 'GET') {
      exige(s, 'ADMIN', 'PORTEIRO', 'MORADOR');
      if (s.perfil === 'MORADOR') {   // só os destinos possíveis de uma visita
        return db.prepare("SELECT id_recurso, nome FROM recurso WHERE id_empresa = ? AND tipo = 'F' ORDER BY nome").all(s.empresa);
      }
      return db.prepare('SELECT id_recurso, nome, criticidade, tipo FROM recurso WHERE id_empresa = ? ORDER BY tipo DESC, nome COLLATE NOCASE').all(s.empresa);
    }
    if (pathname === '/api/recursos' && metodo === 'POST') {
      exige(s, 'ADMIN');
      const b = await lerJson(req);
      const nome = txt(b.nome, 120);
      const criticidade = txt(b.criticidade, 5).toUpperCase();
      const tipo = txt(b.tipo, 1).toUpperCase();
      if (nome.length < 3) throw new Erro(400, 'Informe o nome do local.');
      if (!['BAIXA', 'MEDIA', 'ALTA'].includes(criticidade)) throw new Erro(400, 'Criticidade inválida.');
      if (!['L', 'F'].includes(tipo)) throw new Erro(400, 'Tipo inválido (L = lógico, F = físico).');
      const id = transacao(() => {
        const r = db.prepare('INSERT INTO recurso (id_empresa, nome, criticidade, tipo) VALUES (?, ?, ?, ?)').run(s.empresa, nome, criticidade, tipo);
        const novo = Number(r.lastInsertRowid);
        db.prepare(tipo === 'F' ? 'INSERT INTO recurso_fisico (id_recurso) VALUES (?)' : 'INSERT INTO recurso_logico (id_recurso) VALUES (?)').run(novo);
        return novo;
      });
      audita(s, 'RECURSO_CRIADO', `id ${id} (${tipo === 'F' ? 'físico' : 'lógico'}, criticidade ${criticidade})`);
      return { id_recurso: id };
    }
    if ((m = pathname.match(/^\/api\/recursos\/(\d+)$/))) {
      exige(s, 'ADMIN');
      const id = Number(m[1]);
      const r = recursoDaEmpresa(id, s.empresa);
      if (!r) throw new Erro(404, 'Local não encontrado.');
      if (metodo === 'GET') return { id_recurso: r.id_recurso, nome: r.nome, criticidade: r.criticidade, tipo: r.tipo };
      if (metodo === 'PUT') {
        const b = await lerJson(req);
        const nome = txt(b.nome, 120);
        const criticidade = txt(b.criticidade, 5).toUpperCase();
        if (nome.length < 3) throw new Erro(400, 'Informe o nome do local.');
        if (!['BAIXA', 'MEDIA', 'ALTA'].includes(criticidade)) throw new Erro(400, 'Criticidade inválida.');
        db.prepare('UPDATE recurso SET nome = ?, criticidade = ? WHERE id_recurso = ?').run(nome, criticidade, id);
        audita(s, 'RECURSO_ALTERADO', `id ${id}${r.criticidade !== criticidade ? ` | criticidade ${r.criticidade}→${criticidade}` : ''}`);
        return { ok: true };
      }
      if (metodo === 'DELETE') {
        try { db.prepare('DELETE FROM recurso WHERE id_recurso = ?').run(id); }
        catch (e) { return emUso(e, 'Este local já tem registros de acesso ou visitas e não pode ser excluído.'); }
        audita(s, 'RECURSO_EXCLUIDO', `id ${id}`);
        return { ok: true };
      }
    }

    // ---- liberação de acesso (autorizacao) ----
    if (pathname === '/api/autorizacoes' && metodo === 'GET') {
      exige(s, 'ADMIN', 'PORTEIRO', 'MORADOR');
      const dia = hoje();
      const linhas = db.prepare(
        `SELECT a.id_usuario, a.id_recurso, u.nome AS pessoa, u.unidade, r.nome AS local, r.criticidade, a.inicio, a.fim, a.situacao
         FROM autorizacao a JOIN usuario u ON u.id_usuario = a.id_usuario JOIN recurso r ON r.id_recurso = a.id_recurso
         WHERE u.id_empresa = ? ${s.perfil === 'MORADOR' ? 'AND a.id_usuario = ?' : ''}
         ORDER BY u.nome COLLATE NOCASE, r.nome`).all(...(s.perfil === 'MORADOR' ? [s.empresa, s.id] : [s.empresa]));
      return linhas.map((a) => ({ ...a, vigencia: vigencia(a, dia) }));
    }
    if (pathname === '/api/autorizacoes' && metodo === 'POST') {
      exige(s, 'ADMIN');
      const b = await lerJson(req);
      const idu = inteiro(b.id_usuario, 'Escolha a pessoa.');
      const idr = inteiro(b.id_recurso, 'Escolha o local.');
      const inicio = txt(b.inicio, 10);
      const fim = txt(b.fim, 10) || null;
      const situacao = txt(b.situacao || 'ATIVA', 10).toUpperCase();
      if (!usuarioDaEmpresa(idu, s.empresa)) throw new Erro(404, 'Pessoa não encontrada.');
      if (!recursoDaEmpresa(idr, s.empresa)) throw new Erro(404, 'Local não encontrado.');
      if (!dataOk(inicio)) throw new Erro(400, 'Informe a data de início (AAAA-MM-DD).');
      if (fim && (!dataOk(fim) || fim < inicio)) throw new Erro(400, 'A data final deve ser válida e não anterior ao início.');
      if (!['ATIVA', 'SUSPENSA'].includes(situacao)) throw new Erro(400, 'Situação inválida.');
      const existia = db.prepare('SELECT 1 FROM autorizacao WHERE id_usuario = ? AND id_recurso = ?').get(idu, idr);
      db.prepare(
        `INSERT INTO autorizacao (id_usuario, id_recurso, inicio, fim, situacao) VALUES (?, ?, ?, ?, ?)
         ON CONFLICT (id_usuario, id_recurso) DO UPDATE SET inicio = excluded.inicio, fim = excluded.fim, situacao = excluded.situacao`)
        .run(idu, idr, inicio, fim, situacao);
      audita(s, existia ? 'AUTORIZACAO_ALTERADA' : 'AUTORIZACAO_LIBERADA', `usuario ${idu} em recurso ${idr} (${inicio} a ${fim ?? 'sem prazo'}, ${situacao})`);
      return { ok: true };
    }
    if ((m = pathname.match(/^\/api\/autorizacoes\/(\d+)\/(\d+)$/)) && metodo === 'DELETE') {
      exige(s, 'ADMIN');
      const idu = Number(m[1]);
      const idr = Number(m[2]);
      if (!usuarioDaEmpresa(idu, s.empresa)) throw new Erro(404, 'Autorização não encontrada.');
      const r = db.prepare('DELETE FROM autorizacao WHERE id_usuario = ? AND id_recurso = ?').run(idu, idr);
      if (!r.changes) throw new Erro(404, 'Autorização não encontrada.');
      audita(s, 'AUTORIZACAO_REVOGADA', `usuario ${idu} em recurso ${idr}`);
      return { ok: true };
    }

    // ---- portaria: a catraca decide e registra ----
    if (pathname === '/api/portaria/leitores' && metodo === 'GET') {
      exige(s, 'ADMIN', 'PORTEIRO');
      return db.prepare(
        `SELECT c.id_credencial, u.nome, u.unidade, u.situacao FROM credencial c JOIN usuario u ON u.id_usuario = c.id_usuario
         WHERE c.tipo = 'C' AND u.id_empresa = ? ORDER BY u.nome COLLATE NOCASE`).all(s.empresa);
    }
    if (pathname === '/api/portaria/acesso' && metodo === 'POST') {
      exige(s, 'ADMIN', 'PORTEIRO');
      const b = await lerJson(req);
      return decidirAcesso(s.empresa, inteiro(b.id_credencial, 'Escolha o crachá.'), inteiro(b.id_recurso, 'Escolha o local.'));
    }
    if (pathname === '/api/tentativas' && metodo === 'GET') {
      exige(s, 'ADMIN', 'PORTEIRO', 'MORADOR');
      const filtro = url.searchParams.get('resultado');
      const limite = Math.min(Math.max(Number(url.searchParams.get('limite')) || 100, 1), 300);
      const so_dele = s.perfil === 'MORADOR';
      const sql =
        `SELECT t.id_tentativa, t.data_hora, u.nome AS pessoa, u.unidade, r.nome AS local, t.resultado, t.motivo_recusa
         FROM tentativa t JOIN recurso r ON r.id_recurso = t.id_recurso LEFT JOIN usuario u ON u.id_usuario = t.id_usuario
         WHERE r.id_empresa = ? ${so_dele ? 'AND t.id_usuario = ?' : ''} ${['PERMITIDO', 'NEGADO'].includes(filtro) ? 'AND t.resultado = ?' : ''}
         ORDER BY t.id_tentativa DESC LIMIT ?`;
      const p = [s.empresa];
      if (so_dele) p.push(s.id);
      if (['PERMITIDO', 'NEGADO'].includes(filtro)) p.push(filtro);
      p.push(limite);
      return db.prepare(sql).all(...p);
    }

    // ---- visitantes e visitas ----
    if (pathname === '/api/visitantes' && metodo === 'GET') {
      exige(s, 'ADMIN', 'PORTEIRO');
      const q = txt(url.searchParams.get('q'), 60);
      const dig = so(q);
      const idx = dig.length === 11 ? cripto.indice(dig, 'visitante.cpf') : null;
      return db.prepare(
        `SELECT id_visitante, nome, cpf, telefone, criado_em FROM visitante
         WHERE id_empresa = ? AND (nome LIKE ? ESCAPE '\\' OR cpf_idx = ?) ORDER BY nome COLLATE NOCASE LIMIT 500`)
        .all(s.empresa, likeDe(q), idx).map(db.decifraVisitante)
        .map((v) => ({ ...v, cpf: s.perfil === 'ADMIN' ? v.cpf : mascaraCpf(v.cpf) }));
    }
    if (pathname === '/api/visitantes' && metodo === 'POST') {
      exige(s, 'ADMIN', 'PORTEIRO');
      const d = dadosVisitante(await lerJson(req));
      try {
        const c = db.cifraVisitante(d);
        const r = db.prepare('INSERT INTO visitante (id_empresa, nome, cpf, cpf_idx, telefone) VALUES (?, ?, ?, ?, ?)')
          .run(s.empresa, d.nome, c.cpf, c.cpf_idx, c.telefone);
        audita(s, 'VISITANTE_CRIADO', `id ${r.lastInsertRowid}`);
        return { id_visitante: Number(r.lastInsertRowid) };
      } catch (e) { return unico(e, 'Já existe um visitante com este CPF.'); }
    }
    if ((m = pathname.match(/^\/api\/visitantes\/(\d+)$/)) && metodo === 'DELETE') {
      exige(s, 'ADMIN');   // direito de apagar (LGPD): só o administrador, e só se o visitante não tiver visitas
      const id = Number(m[1]);
      try {
        const r = db.prepare('DELETE FROM visitante WHERE id_visitante = ? AND id_empresa = ?').run(id, s.empresa);
        if (!r.changes) throw new Erro(404, 'Visitante não encontrado.');
      } catch (e) { return emUso(e, 'Este visitante tem visitas registradas e não pode ser excluído.'); }
      audita(s, 'VISITANTE_EXCLUIDO', `id ${id}`);
      return { ok: true };
    }
    if (pathname === '/api/visitas' && metodo === 'GET') {
      exige(s, 'ADMIN', 'PORTEIRO', 'MORADOR');
      return db.prepare(
        `SELECT v.id_visita, v.data_prevista, v.status, vi.nome AS visitante, a.nome AS anfitriao, a.unidade, r.nome AS destino
         FROM visita v JOIN visitante vi ON vi.id_visitante = v.id_visitante
         JOIN usuario a ON a.id_usuario = v.id_anfitriao JOIN recurso r ON r.id_recurso = v.id_recurso
         WHERE v.id_empresa = ? ${s.perfil === 'MORADOR' ? 'AND v.id_anfitriao = ?' : ''}
         ORDER BY v.data_prevista DESC LIMIT 300`).all(...(s.perfil === 'MORADOR' ? [s.empresa, s.id] : [s.empresa]));
    }
    if (pathname === '/api/visitas' && metodo === 'POST') {
      exige(s, 'ADMIN', 'PORTEIRO', 'MORADOR');
      const b = await lerJson(req);
      const d = dadosVisitante({ nome: b.visitante_nome, cpf: b.cpf, telefone: b.telefone });
      const quando = txt(b.data_prevista, 16);
      const idr = inteiro(b.id_recurso, 'Escolha o destino da visita.');
      if (!dataHoraOk(quando)) throw new Erro(400, 'Informe a data e a hora previstas.');
      const destino = recursoDaEmpresa(idr, s.empresa);
      if (!destino || destino.tipo !== 'F') throw new Erro(400, 'O destino deve ser um local físico.');
      const anfitriao = s.perfil === 'MORADOR' ? s.id : inteiro(b.id_anfitriao, 'Escolha quem recebe a visita.');
      if (!usuarioDaEmpresa(anfitriao, s.empresa)) throw new Erro(404, 'Anfitrião não encontrado.');
      const id = transacao(() => {
        const idv = acharOuCriaVisitante(s.empresa, d);
        const r = db.prepare('INSERT INTO visita (id_empresa, id_visitante, id_anfitriao, id_recurso, data_prevista) VALUES (?, ?, ?, ?, ?)')
          .run(s.empresa, idv, anfitriao, idr, quando);
        return Number(r.lastInsertRowid);
      });
      audita(s, 'VISITA_AGENDADA', `id ${id} para ${quando}`);
      return { id_visita: id };
    }
    if ((m = pathname.match(/^\/api\/visitas\/(\d+)\/status$/)) && metodo === 'PUT') {
      exige(s, 'ADMIN', 'PORTEIRO', 'MORADOR');
      const id = Number(m[1]);
      const novo = txt((await lerJson(req)).status, 10).toUpperCase();
      const v = db.prepare('SELECT * FROM visita WHERE id_visita = ? AND id_empresa = ?').get(id, s.empresa);
      if (!v || (s.perfil === 'MORADOR' && v.id_anfitriao !== s.id)) throw new Erro(404, 'Visita não encontrada.');
      const permitido = s.perfil === 'MORADOR'
        ? { AGENDADA: ['CANCELADA'], AUTORIZADA: ['CANCELADA'] }
        : { AGENDADA: ['AUTORIZADA', 'NEGADA', 'CANCELADA'], AUTORIZADA: ['REALIZADA', 'NEGADA', 'CANCELADA'] };
      if (!(permitido[v.status] || []).includes(novo)) throw new Erro(400, `Não é possível passar a visita de ${v.status} para ${novo}.`);
      db.prepare('UPDATE visita SET status = ? WHERE id_visita = ?').run(novo, id);
      audita(s, 'VISITA_' + novo, `id ${id}`);
      return { ok: true };
    }

    // ---- auditoria ----
    if (pathname === '/api/auditoria' && metodo === 'GET') {
      exige(s, 'ADMIN');
      return db.prepare(
        `SELECT l.id_log, l.momento, l.acao, l.detalhe, u.nome AS pessoa
         FROM log_auditoria l LEFT JOIN usuario u ON u.id_usuario = l.id_usuario
         WHERE l.id_empresa = ? OR l.id_empresa IS NULL ORDER BY l.id_log DESC LIMIT 200`).all(s.empresa);
    }

    throw new Erro(404, 'Rota não encontrada.');
  }

  return { handler, decidirAcesso, hoje, hashSenha };
};
