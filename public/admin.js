'use strict';
(() => {
  const $ = (id) => document.getElementById(id);
  let eu = null;            // { id, nome, perfil, empresa, unidade }
  let pagina = null;        // id da página aberta
  let formAtual = null;     // { aoSalvar }

  // ------------------------------------------------------------ utilidades
  async function api(url, opcoes = {}) {
    const init = { method: opcoes.method || 'GET', credentials: 'same-origin', headers: {} };
    if (opcoes.corpo !== undefined) {
      init.headers['Content-Type'] = 'application/json';
      init.body = JSON.stringify(opcoes.corpo);
    }
    const r = await fetch(url, init);
    const dados = await r.json().catch(() => ({}));
    if (r.status === 401 && url !== '/api/login') { eu = null; mostra('login'); throw new Error('Sessão expirada. Entre novamente.'); }
    if (!r.ok) throw new Error(dados.erro || 'Erro inesperado.');
    return dados;
  }
  function el(tag, props = {}, ...filhos) {
    const e = document.createElement(tag);
    for (const [k, v] of Object.entries(props)) {
      if (k === 'class') e.className = v;
      else if (k.startsWith('on')) e.addEventListener(k.slice(2), v);
      else if (v !== false && v != null) e.setAttribute(k, v === true ? '' : v);
    }
    for (const f of filhos) if (f != null) e.append(f.nodeType ? f : document.createTextNode(String(f)));
    return e;
  }
  const iniciais = (n) => String(n).trim().split(/\s+/).filter(Boolean).slice(0, 2).map((p) => p[0]).join('').toUpperCase();
  const celNome = (n, sub) => el('div', { class: 'nome-cel' }, el('span', { class: 'avatar' }, iniciais(n)), el('span', {}, n, sub ? el('small', { class: 'sub-cel' }, sub) : null));
  const dataBr = (iso) => (iso ? iso.slice(0, 10).split('-').reverse().join('/') : '');
  const quando = (utc) => { const d = new Date(String(utc).replace(' ', 'T') + 'Z'); return isNaN(d) ? utc : d.toLocaleString('pt-BR', { day: '2-digit', month: '2-digit', year: 'numeric', hour: '2-digit', minute: '2-digit', hour12: false }); };
  const quandoLocal = (v) => { const [d, h] = String(v).split('T'); return `${dataBr(d)} ${h || ''}`.trim(); };
  const hojeIso = () => new Date().toLocaleDateString('sv-SE');
  const cpfFmt = (c) => (/^\d{11}$/.test(c) ? c.replace(/(\d{3})(\d{3})(\d{3})(\d{2})/, '$1.$2.$3-$4') : c);
  const telFmt = (t) => {
    const d = String(t || '').replace(/\D/g, '');
    if (d.length === 11) return d.replace(/(\d{2})(\d{5})(\d{4})/, '($1) $2-$3');
    if (d.length === 10) return d.replace(/(\d{2})(\d{4})(\d{4})/, '($1) $2-$3');
    return t || '';
  };
  const cpfParcial = (d) => d.replace(/^(\d{3})(\d)/, '$1.$2').replace(/^(\d{3})\.(\d{3})(\d)/, '$1.$2.$3').replace(/^(\d{3})\.(\d{3})\.(\d{3})(\d)/, '$1.$2.$3-$4');
  const telParcial = (d) => (d.length > 10 ? telFmt(d) : d.length > 6 ? `(${d.slice(0, 2)}) ${d.slice(2, 6)}-${d.slice(6)}` : d.length > 2 ? `(${d.slice(0, 2)}) ${d.slice(2)}` : d);

  const PERFIL = { ADMIN: 'Administrador', PORTEIRO: 'Porteiro', MORADOR: 'Morador' };
  const TIPO_CRED = { C: 'Crachá (acesso físico)', T: 'Cartão (acesso ao sistema)' };
  const TOM = {
    ATIVO: 'ok', PERMITIDO: 'ok', VIGENTE: 'ok', AUTORIZADA: 'ok', REALIZADA: 'ok', ATIVA: 'ok',
    BLOQUEADO: 'off', INATIVO: 'off', NEGADO: 'off', VENCIDA: 'off', SUSPENSA: 'off', NEGADA: 'off', CANCELADA: 'off',
  };
  const ROTULO = { AGENDADA: 'Agendada', AUTORIZADA: 'Autorizada', REALIZADA: 'Realizada', NEGADA: 'Negada', CANCELADA: 'Cancelada',
    PERMITIDO: 'Permitido', NEGADO: 'Negado', VIGENTE: 'Vigente', VENCIDA: 'Vencida', SUSPENSA: 'Suspensa', FUTURA: 'Ainda não iniciada',
    ATIVO: 'Ativo', INATIVO: 'Inativo', BLOQUEADO: 'Bloqueado' };
  const tag = (v) => el('span', { class: 'tag ' + (TOM[v] || '') }, ROTULO[v] || v);

  function mensagem(texto, ok) {
    const m = $('app-msg');
    m.textContent = texto || '';
    m.className = 'msg' + (ok ? ' ok' : '');
  }
  function mostra(tela) {
    $('tela-login').hidden = tela !== 'login';
    $('tela-app').hidden = tela !== 'app';
    if (tela === 'login') $('login-email').focus();
  }
  const botao = (rot, classe, fn) => el('button', { class: 'btn small ' + classe, type: 'button', onclick: fn }, rot);
  const pergunta = (texto) => window.confirm(texto);
  async function executa(fn, ok) {
    try { await fn(); mensagem(ok, true); await recarrega(); } catch (e) { mensagem(e.message); }
  }

  // ------------------------------------------------------------ formulários
  /** campos: [{ n, r, tipo, req, cheio, max, opcoes: [[valor, rótulo]] | async () => [...], mascara, dica }] */
  async function abreForm(titulo, campos, valores, aoSalvar, rotuloSalvar = 'Salvar') {
    $('dialogo-titulo').textContent = titulo;
    $('form-msg').textContent = '';
    $('btn-salvar').textContent = rotuloSalvar;
    const caixa = $('campos');
    caixa.replaceChildren();
    for (const c of campos) {
      const id = 'f-' + c.n;
      let campo;
      if (c.opcoes) {
        const lista = typeof c.opcoes === 'function' ? await c.opcoes() : c.opcoes;
        campo = el('select', { id, name: c.n, required: c.req, disabled: c.travado });
        for (const [v, rot] of lista) campo.append(el('option', { value: v }, rot));
      } else {
        campo = el('input', {
          id, name: c.n, type: c.tipo || 'text', required: c.req, maxlength: c.max, disabled: c.travado,
          autocomplete: c.tipo === 'password' ? 'new-password' : 'off', inputmode: c.modo,
        });
        if (c.mascara) campo.addEventListener('input', () => {
          const d = campo.value.replace(/\D/g, '');
          campo.value = c.mascara === 'cpf' ? cpfParcial(d.slice(0, 11)) : telParcial(d.slice(0, 11));
        });
      }
      const v = valores?.[c.n];
      if (v !== undefined && v !== null) campo.value = c.mascara === 'cpf' ? cpfFmt(v) : c.mascara === 'tel' ? telFmt(v) : v;
      caixa.append(el('div', { class: 'campo' + (c.cheio ? ' cheio' : '') }, el('label', { for: id }, c.r + (c.req ? ' *' : '')), campo, c.dica ? el('small', { class: 'dica' }, c.dica) : null));
    }
    formAtual = { aoSalvar, campos };
    $('dialogo').showModal();
    caixa.querySelector('input:not([disabled]),select:not([disabled])')?.focus();
  }
  async function salva(ev) {
    ev.preventDefault();
    if (!formAtual) return;
    const corpo = {};
    $('campos').querySelectorAll('input,select').forEach((c) => { if (!c.disabled) corpo[c.name] = c.value; });
    const msg = $('form-msg');
    msg.textContent = '';
    $('btn-salvar').disabled = true;
    try {
      await formAtual.aoSalvar(corpo);
      $('dialogo').close();
      mensagem('Salvo com sucesso.', true);
      await recarrega();
    } catch (e) { msg.textContent = e.message; }
    finally { $('btn-salvar').disabled = false; }
  }

  // opções reutilizáveis
  const optPessoas = (so_ativos) => async () => {
    const l = await api('/api/usuarios');
    return l.filter((u) => !so_ativos || u.situacao === 'ATIVO').map((u) => [u.id_usuario, `${u.nome} (${u.unidade})`]);
  };
  const optLocais = (tipo) => async () => (await api('/api/recursos')).filter((r) => !tipo || r.tipo === tipo).map((r) => [r.id_recurso, r.nome]);

  // ------------------------------------------------------------ tabelas
  function tabela(cabecalhos, linhas, vazio) {
    const t = $('tabela');
    $('tabela').parentElement.hidden = false;
    if (!linhas.length) { t.replaceChildren(el('tbody', {}, el('tr', {}, el('td', { class: 'vazio' }, vazio || 'Nada por aqui ainda.')))); return; }
    t.replaceChildren(
      el('thead', {}, el('tr', {}, ...cabecalhos.map((h) => el('th', { scope: 'col' }, h)))),
      el('tbody', {}, ...linhas.map((cels) => el('tr', {}, ...cels.map((c, i) => el('td', { class: c && c.acoes ? 'acoes' : '' }, ...(c && c.acoes ? c.acoes : [c])))))));
  }
  const acoes = (...bs) => ({ acoes: bs.filter(Boolean) });

  // ------------------------------------------------------------ páginas
  const eAdmin = () => eu.perfil === 'ADMIN';
  const PAGINAS = {
    resumo: {
      perfis: ['ADMIN', 'PORTEIRO'], icone: '📊', rot: 'Visão geral', sub: 'O que aconteceu hoje na portaria.',
      async carrega() {
        const r = await api('/api/resumo');
        const C = (emoji, tom, v, rot) => el('div', { class: 'card sombra' }, el('div', { class: 'emoji ' + tom }, emoji), el('div', {}, el('strong', {}, v), el('small', {}, rot)));
        $('estat').hidden = false;
        $('estat').replaceChildren(
          C('✅', 'tom-verde', r.permitidas, 'passagens permitidas hoje'), C('🚫', 'tom-rosa', r.negadas, 'passagens negadas hoje'),
          C('🧑‍🤝‍🧑', 'tom-azul', r.visitasHoje, 'visitas previstas hoje'), C('👥', 'tom-roxo', r.pessoasAtivas, 'pessoas ativas'),
          C('⛔', 'tom-laranja', r.bloqueadas, 'bloqueadas ou inativas'), C('🔑', 'tom-ciano', r.autorizacoes, 'autorizações vigentes'));
        await PAGINAS.acessos.carrega({ limite: 8 });
      },
    },
    portaria: {
      perfis: ['ADMIN', 'PORTEIRO'], icone: '🚪', rot: 'Portaria', sub: 'Passe o crachá em uma porta: o sistema decide pela regra e registra a passagem.',
      async carrega() {
        $('portaria').hidden = false;
        const leitores = await api('/api/portaria/leitores');
        const locais = (await api('/api/recursos')).filter((r) => r.tipo === 'F');
        $('p-leitor').replaceChildren(...leitores.map((l) => el('option', { value: l.id_credencial }, `${l.nome} (${l.unidade})${l.situacao !== 'ATIVO' ? ' · ' + l.situacao.toLowerCase() : ''}`)), el('option', { value: '999999' }, 'Crachá não cadastrado'));
        $('p-local').replaceChildren(...locais.map((l) => el('option', { value: l.id_recurso }, l.nome)));
        await PAGINAS.acessos.carrega({ limite: 10 });
      },
    },
    acessos: {
      perfis: ['ADMIN', 'PORTEIRO', 'MORADOR'], icone: '🧾', rot: (p) => (p === 'MORADOR' ? 'Meus acessos' : 'Registro de acessos'),
      sub: 'Cada tentativa de passagem, permitida ou negada, com o motivo. Este registro não pode ser alterado nem apagado.',
      filtro: [['', 'Todas as passagens'], ['PERMITIDO', 'Só permitidas'], ['NEGADO', 'Só negadas']],
      async carrega(opc = {}) {
        const f = $('filtro').hidden ? '' : $('filtro').value;
        const l = await api(`/api/tentativas?limite=${opc.limite || 100}${f ? '&resultado=' + f : ''}`);
        tabela(['Quando', 'Pessoa', 'Local', 'Resultado', 'Motivo'], l.map((t) => [quando(t.data_hora), t.pessoa ? celNome(t.pessoa, t.unidade) : el('em', {}, 'Crachá não cadastrado'), t.local, tag(t.resultado), t.motivo_recusa || '—']), 'Nenhuma passagem registrada ainda.');
      },
    },
    visitas: {
      perfis: ['ADMIN', 'PORTEIRO', 'MORADOR'], icone: '🧑‍🤝‍🧑', rot: (p) => (p === 'MORADOR' ? 'Minhas visitas' : 'Visitas'),
      sub: (p) => (p === 'MORADOR' ? 'Agende quem vai visitar você; a portaria autoriza a entrada.' : 'Visitas agendadas pelos moradores. A portaria autoriza, nega ou marca como realizada.'),
      novo: { rot: '+ Agendar visita', perfis: ['ADMIN', 'PORTEIRO', 'MORADOR'] },
      async carrega() {
        const l = await api('/api/visitas');
        const mudar = (id, status, ok) => executa(() => api(`/api/visitas/${id}/status`, { method: 'PUT', corpo: { status } }), ok);
        tabela(['Quando', 'Visitante', 'Quem recebe', 'Destino', 'Situação', ''], l.map((v) => {
          const pode = [];
          if (eu.perfil === 'MORADOR') { if (['AGENDADA', 'AUTORIZADA'].includes(v.status)) pode.push(botao('Cancelar', 'ghost', () => pergunta('Cancelar esta visita?') && mudar(v.id_visita, 'CANCELADA', 'Visita cancelada.'))); }
          else {
            if (v.status === 'AGENDADA') pode.push(botao('Autorizar', '', () => mudar(v.id_visita, 'AUTORIZADA', 'Visita autorizada.')));
            if (v.status === 'AUTORIZADA') pode.push(botao('Entrou', '', () => mudar(v.id_visita, 'REALIZADA', 'Visita registrada como realizada.')));
            if (['AGENDADA', 'AUTORIZADA'].includes(v.status)) pode.push(botao('Negar', 'danger', () => pergunta('Negar a entrada desta visita?') && mudar(v.id_visita, 'NEGADA', 'Visita negada.')));
          }
          return [quandoLocal(v.data_prevista), v.visitante, celNome(v.anfitriao, v.unidade), v.destino, tag(v.status), acoes(...pode)];
        }), 'Nenhuma visita agendada.');
      },
      abre() {
        const campos = [
          { n: 'visitante_nome', r: 'Nome do visitante', req: true, cheio: true, max: 120 },
          { n: 'cpf', r: 'CPF do visitante', req: true, mascara: 'cpf', max: 14, modo: 'numeric' },
          { n: 'telefone', r: 'Telefone', mascara: 'tel', max: 15, modo: 'tel' },
          { n: 'id_recurso', r: 'Destino', req: true, opcoes: optLocais('F') },
          { n: 'data_prevista', r: 'Data e hora previstas', req: true, tipo: 'datetime-local' },
        ];
        if (eu.perfil !== 'MORADOR') campos.push({ n: 'id_anfitriao', r: 'Quem recebe a visita', req: true, cheio: true, opcoes: optPessoas(true) });
        return abreForm('Agendar visita', campos, {}, (c) => api('/api/visitas', { method: 'POST', corpo: c }), 'Agendar');
      },
    },
    autorizacoes: {
      perfis: ['ADMIN', 'PORTEIRO', 'MORADOR'], icone: '✅', rot: (p) => (p === 'MORADOR' ? 'Minhas autorizações' : 'Autorizações'),
      sub: (p) => (p === 'MORADOR' ? 'Os locais em que você pode entrar e até quando.' : 'Liberação de acesso: quem pode usar qual local, de quando até quando. A catraca consulta esta lista.'),
      novo: { rot: '+ Liberar acesso', perfis: ['ADMIN'] },
      async carrega() {
        const l = await api('/api/autorizacoes');
        tabela(['Pessoa', 'Local', 'Início', 'Fim', 'Situação', ...(eAdmin() ? [''] : [])], l.map((a) => [
          celNome(a.pessoa, a.unidade), a.local, dataBr(a.inicio), a.fim ? dataBr(a.fim) : 'sem prazo', tag(a.vigencia),
          ...(eAdmin() ? [acoes(
            botao('Editar', 'ghost', () => PAGINAS.autorizacoes.abre(a)),
            botao(a.situacao === 'ATIVA' ? 'Suspender' : 'Reativar', 'ghost', () => executa(() => api('/api/autorizacoes', { method: 'POST', corpo: { id_usuario: a.id_usuario, id_recurso: a.id_recurso, inicio: a.inicio, fim: a.fim || '', situacao: a.situacao === 'ATIVA' ? 'SUSPENSA' : 'ATIVA' } }), a.situacao === 'ATIVA' ? 'Autorização suspensa.' : 'Autorização reativada.')),
            botao('Revogar', 'danger', () => pergunta(`Revogar o acesso de ${a.pessoa} em "${a.local}"?`) && executa(() => api(`/api/autorizacoes/${a.id_usuario}/${a.id_recurso}`, { method: 'DELETE' }), 'Autorização revogada.')))] : []),
        ]), 'Nenhuma autorização cadastrada.');
      },
      abre(a) {
        return abreForm(a ? 'Editar autorização' : 'Liberar acesso', [
          { n: 'id_usuario', r: 'Pessoa', req: true, cheio: true, travado: !!a, opcoes: optPessoas(false) },
          { n: 'id_recurso', r: 'Local ou sistema', req: true, cheio: true, travado: !!a, opcoes: optLocais() },
          { n: 'inicio', r: 'Vale a partir de', req: true, tipo: 'date' },
          { n: 'fim', r: 'Vale até (vazio = sem prazo)', tipo: 'date' },
          { n: 'situacao', r: 'Situação', req: true, opcoes: [['ATIVA', 'Ativa'], ['SUSPENSA', 'Suspensa']] },
        ], a ? { id_usuario: a.id_usuario, id_recurso: a.id_recurso, inicio: a.inicio, fim: a.fim || '', situacao: a.situacao } : { inicio: hojeIso(), situacao: 'ATIVA' },
        (c) => api('/api/autorizacoes', { method: 'POST', corpo: a ? { ...c, id_usuario: a.id_usuario, id_recurso: a.id_recurso } : c }), a ? 'Salvar' : 'Liberar');
      },
    },
    visitantes: {
      perfis: ['ADMIN', 'PORTEIRO'], icone: '📇', rot: 'Visitantes', sub: 'Cadastro de visitantes. CPF e telefone ficam cifrados no banco.',
      busca: 'Buscar por nome ou CPF completo',
      novo: { rot: '+ Novo visitante', perfis: ['ADMIN', 'PORTEIRO'] },
      async carrega() {
        const l = await api('/api/visitantes?q=' + encodeURIComponent($('busca').value.trim()));
        tabela(['Nome', 'CPF', 'Telefone', 'Cadastro', ...(eAdmin() ? [''] : [])], l.map((v) => [celNome(v.nome), cpfFmt(v.cpf), telFmt(v.telefone), quando(v.criado_em),
          ...(eAdmin() ? [acoes(botao('Excluir', 'danger', () => pergunta(`Excluir ${v.nome}? Os dados do visitante serão apagados.`) && executa(() => api('/api/visitantes/' + v.id_visitante, { method: 'DELETE' }), 'Visitante excluído.')))] : [])]), 'Nenhum visitante encontrado.');
      },
      abre() {
        return abreForm('Novo visitante', [
          { n: 'nome', r: 'Nome completo', req: true, cheio: true, max: 120 },
          { n: 'cpf', r: 'CPF', req: true, mascara: 'cpf', max: 14, modo: 'numeric' },
          { n: 'telefone', r: 'Telefone', mascara: 'tel', max: 15, modo: 'tel' },
        ], {}, (c) => api('/api/visitantes', { method: 'POST', corpo: c }), 'Cadastrar');
      },
    },
    pessoas: {
      perfis: ['ADMIN', 'PORTEIRO'], icone: '👥', rot: 'Pessoas', busca: 'Buscar por nome, unidade ou e-mail',
      sub: (p) => (p === 'ADMIN' ? 'Moradores, funcionários e porteiros. Bloquear uma pessoa vale na hora, em todas as portas.' : 'Consulta de moradores e funcionários.'),
      novo: { rot: '+ Nova pessoa', perfis: ['ADMIN'] },
      async carrega() {
        const l = await api('/api/usuarios?q=' + encodeURIComponent($('busca').value.trim()));
        const cab = ['Nome', 'Perfil', 'Situação', ...(eAdmin() ? ['E-mail', 'Credenciais', ''] : [])];
        tabela(cab, l.map((u) => [celNome(u.nome, u.unidade), PERFIL[u.perfil], tag(u.situacao),
          ...(eAdmin() ? [u.email, String(u.credenciais), acoes(
            botao('Editar', 'ghost', () => PAGINAS.pessoas.abre(u.id_usuario)),
            botao(u.situacao === 'BLOQUEADO' ? 'Desbloquear' : 'Bloquear', u.situacao === 'BLOQUEADO' ? 'ghost' : 'danger', () => PAGINAS.pessoas.alterna(u)))] : [])]), 'Nenhuma pessoa encontrada.');
      },
      async alterna(u) {
        const bloqueando = u.situacao !== 'BLOQUEADO';
        if (bloqueando && !pergunta(`Bloquear ${u.nome}? O acesso é cortado na hora, em todas as portas.`)) return;
        await executa(async () => {
          const completo = await api('/api/usuarios/' + u.id_usuario);
          await api('/api/usuarios/' + u.id_usuario, { method: 'PUT', corpo: { ...completo, situacao: bloqueando ? 'BLOQUEADO' : 'ATIVO' } });
        }, bloqueando ? 'Pessoa bloqueada.' : 'Pessoa desbloqueada.');
      },
      async abre(id) {
        const v = id ? await api('/api/usuarios/' + id) : { perfil: 'MORADOR', situacao: 'ATIVO' };
        return abreForm(id ? 'Editar pessoa' : 'Nova pessoa', [
          { n: 'nome', r: 'Nome completo', req: true, cheio: true, max: 120 },
          { n: 'unidade', r: 'Unidade (apto, sala ou setor)', req: true, max: 80 },
          { n: 'email', r: 'E-mail', req: true, tipo: 'email', max: 160 },
          { n: 'perfil', r: 'Perfil', req: true, opcoes: Object.entries(PERFIL) },
          { n: 'situacao', r: 'Situação', req: true, opcoes: [['ATIVO', 'Ativo'], ['INATIVO', 'Inativo'], ['BLOQUEADO', 'Bloqueado']] },
          ...(id ? [] : [{ n: 'senha', r: 'Senha de acesso ao painel (opcional)', tipo: 'password', cheio: true, max: 128, dica: 'Se informada, cria um cartão de acesso ao painel. Mínimo de 8 caracteres.' }]),
        ], v, (c) => api(id ? '/api/usuarios/' + id : '/api/usuarios', { method: id ? 'PUT' : 'POST', corpo: c }));
      },
    },
    credenciais: {
      perfis: ['ADMIN'], icone: '🔑', rot: 'Credenciais', sub: 'Crachás (acesso às portas) e cartões (acesso ao sistema). A senha é guardada só como hash e ninguém a lê.',
      novo: { rot: '+ Emitir credencial', perfis: ['ADMIN'] },
      async carrega() {
        const l = await api('/api/credenciais');
        tabela(['Pessoa', 'Tipo', 'Situação da pessoa', ''], l.map((c) => [celNome(c.nome, c.unidade), TIPO_CRED[c.tipo], tag(c.situacao), acoes(
          botao('Nova senha', 'ghost', () => PAGINAS.credenciais.novaSenha(c)),
          botao('Revogar', 'danger', () => pergunta(`Revogar o ${c.tipo === 'C' ? 'crachá' : 'cartão'} de ${c.nome}?`) && executa(() => api('/api/credenciais/' + c.id_credencial, { method: 'DELETE' }), 'Credencial revogada.')))]), 'Nenhuma credencial emitida.');
      },
      abre() {
        return abreForm('Emitir credencial', [
          { n: 'id_usuario', r: 'Pessoa', req: true, cheio: true, opcoes: optPessoas(false) },
          { n: 'tipo', r: 'Tipo', req: true, cheio: true, opcoes: Object.entries(TIPO_CRED) },
          { n: 'senha', r: 'Código do crachá ou senha do cartão', req: true, tipo: 'password', cheio: true, max: 128, dica: 'De 8 a 128 caracteres. É guardado só como hash.' },
        ], { tipo: 'C' }, (c) => api('/api/credenciais', { method: 'POST', corpo: c }), 'Emitir');
      },
      novaSenha(c) {
        return abreForm(`Nova senha de ${c.nome}`, [{ n: 'senha', r: 'Nova senha ou código', req: true, tipo: 'password', cheio: true, max: 128, dica: 'De 8 a 128 caracteres.' }], {},
          (v) => api('/api/credenciais/' + c.id_credencial, { method: 'PUT', corpo: v }), 'Redefinir');
      },
    },
    locais: {
      perfis: ['ADMIN', 'PORTEIRO'], icone: '📍', rot: 'Locais e sistemas', sub: 'Portas, salas e sistemas da empresa, cada um com um nível de criticidade.',
      novo: { rot: '+ Novo local', perfis: ['ADMIN'] },
      async carrega() {
        const l = await api('/api/recursos');
        const CRIT = { BAIXA: 'Baixa', MEDIA: 'Média', ALTA: 'Alta' };
        tabela(['Nome', 'Tipo', 'Criticidade', ...(eAdmin() ? [''] : [])], l.map((r) => [r.nome, r.tipo === 'F' ? 'Físico' : 'Lógico (sistema)', el('span', { class: 'tag ' + (r.criticidade === 'ALTA' ? 'off' : '') }, CRIT[r.criticidade]),
          ...(eAdmin() ? [acoes(botao('Editar', 'ghost', () => PAGINAS.locais.abre(r)), botao('Excluir', 'danger', () => pergunta(`Excluir "${r.nome}"?`) && executa(() => api('/api/recursos/' + r.id_recurso, { method: 'DELETE' }), 'Local excluído.')))] : [])]), 'Nenhum local cadastrado.');
      },
      abre(r) {
        return abreForm(r ? 'Editar local' : 'Novo local', [
          { n: 'nome', r: 'Nome', req: true, cheio: true, max: 120 },
          { n: 'tipo', r: 'Tipo', req: true, travado: !!r, opcoes: [['F', 'Físico (porta, sala)'], ['L', 'Lógico (sistema)']] },
          { n: 'criticidade', r: 'Criticidade', req: true, opcoes: [['BAIXA', 'Baixa'], ['MEDIA', 'Média'], ['ALTA', 'Alta']] },
        ], r || { tipo: 'F', criticidade: 'MEDIA' }, (c) => api(r ? '/api/recursos/' + r.id_recurso : '/api/recursos', { method: r ? 'PUT' : 'POST', corpo: c }));
      },
    },
    auditoria: {
      perfis: ['ADMIN'], icone: '🔍', rot: 'Auditoria', sub: 'Quem alterou cadastros, liberações e credenciais. Os valores sensíveis nunca aparecem aqui.',
      async carrega() {
        const l = await api('/api/auditoria');
        tabela(['Quando', 'Quem', 'Ação', 'Detalhe'], l.map((x) => [quando(x.momento), x.pessoa || '—', x.acao, x.detalhe || '']), 'Sem registros.');
      },
    },
    interessados: {
      perfis: ['ADMIN'], icone: '✉️', rot: 'Interessados', sub: 'Pedidos de teste grátis feitos pelo site.',
      async carrega() {
        const l = await api('/api/interesse');
        tabela(['Quando', 'Nome', 'E-mail', 'Condomínio ou empresa', 'Mensagem'], l.map((i) => [quando(i.criado_em), i.nome, i.email, i.clinica || '', i.mensagem || '']), 'Nenhum pedido de teste ainda.');
      },
    },
  };
  const texto = (v) => (typeof v === 'function' ? v(eu.perfil) : v);

  // ------------------------------------------------------------ navegação
  function montaMenu() {
    const nav = $('abas');
    nav.replaceChildren(...Object.entries(PAGINAS).filter(([, p]) => p.perfis.includes(eu.perfil)).map(([id, p]) =>
      el('button', { class: 'nav-item', role: 'tab', 'data-aba': id, 'aria-selected': 'false', onclick: () => vaiPara(id) }, el('span', { class: 'ic' }, p.icone), texto(p.rot))));
  }
  function vaiPara(id) {
    pagina = id;
    const p = PAGINAS[id];
    document.querySelectorAll('.nav-item').forEach((b) => b.setAttribute('aria-selected', String(b.dataset.aba === id)));
    $('titulo-pagina').textContent = texto(p.rot);
    $('subtitulo-pagina').textContent = texto(p.sub) || '';
    const novo = $('btn-novo');
    novo.hidden = !(p.novo && p.novo.perfis.includes(eu.perfil));
    if (p.novo) novo.textContent = p.novo.rot;
    $('busca').value = '';
    $('busca').placeholder = p.busca || 'Buscar';
    $('busca').hidden = !p.busca;
    const f = $('filtro');
    f.hidden = !p.filtro;
    if (p.filtro) f.replaceChildren(...p.filtro.map(([v, r]) => el('option', { value: v }, r)));
    $('ferramentas').hidden = !p.busca && !p.filtro;
    $('estat').hidden = true;
    $('portaria').hidden = true;
    $('p-resultado').replaceChildren();
    recarrega();
  }
  async function recarrega() {
    try { mensagem(''); await PAGINAS[pagina].carrega(); } catch (e) { mensagem(e.message); }
  }

  function entra(u) {
    eu = u;
    $('usuario-nome').textContent = u.nome;
    $('usuario-perfil').textContent = PERFIL[u.perfil];
    $('usuario-avatar').textContent = iniciais(u.nome);
    $('empresa-nome').textContent = (u.empresa || 'MENU').toUpperCase();
    mostra('app');
    montaMenu();
    vaiPara(u.perfil === 'MORADOR' ? 'visitas' : 'resumo');
  }

  // ------------------------------------------------------------ portaria
  async function passarCracha() {
    const caixa = $('p-resultado');
    $('p-passar').disabled = true;
    try {
      const r = await api('/api/portaria/acesso', { method: 'POST', corpo: { id_credencial: Number($('p-leitor').value), id_recurso: Number($('p-local').value) } });
      const ok = r.resultado === 'PERMITIDO';
      caixa.replaceChildren(el('div', { class: 'res-card ' + (ok ? 'res-ok' : 'res-neg') },
        ok ? '✅ Acesso permitido' : '🚫 Acesso negado',
        el('small', {}, `${r.pessoa || 'Crachá não cadastrado'} · ${r.local}${ok ? '' : ' · ' + r.motivo}`)));
      await PAGINAS.acessos.carrega({ limite: 10 });
    } catch (e) { caixa.replaceChildren(el('p', { class: 'msg' }, e.message)); }
    finally { $('p-passar').disabled = false; }
  }

  // ------------------------------------------------------------ eventos
  $('form-login').addEventListener('submit', async (ev) => {
    ev.preventDefault();
    $('login-msg').textContent = '';
    try {
      await api('/api/login', { method: 'POST', corpo: { email: $('login-email').value, senha: $('login-senha').value } });
      $('login-senha').value = '';
      entra(await api('/api/me'));
    } catch (e) { $('login-msg').textContent = e.message; }
  });
  $('btn-sair').addEventListener('click', async () => {
    await api('/api/logout', { method: 'POST', corpo: {} }).catch(() => {});
    eu = null;
    mostra('login');
  });
  $('btn-novo').addEventListener('click', () => PAGINAS[pagina].abre?.());
  $('btn-cancelar').addEventListener('click', () => $('dialogo').close());
  $('form').addEventListener('submit', salva);
  $('p-passar').addEventListener('click', passarCracha);
  $('filtro').addEventListener('change', recarrega);
  let espera;
  $('busca').addEventListener('input', () => { clearTimeout(espera); espera = setTimeout(recarrega, 250); });

  api('/api/me').then(entra).catch(() => mostra('login'));
})();
