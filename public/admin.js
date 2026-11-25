'use strict';
(() => {
  const $ = (id) => document.getElementById(id);
  let eu = null;          // { id, nome, perfil }
  let aba = 'pacientes';
  let editando = null;    // id em edição, ou null para novo

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
  const dataBr = (iso) => (iso ? iso.slice(0, 10).split('-').reverse().join('/') : '');
  const cpfFmt = (c) => (/^\d{11}$/.test(c) ? c.replace(/(\d{3})(\d{3})(\d{3})(\d{2})/, '$1.$2.$3-$4') : c);
  const telFmt = (t) => {
    const d = String(t || '').replace(/\D/g, '');
    if (d.length === 11) return d.replace(/(\d{2})(\d{5})(\d{4})/, '($1) $2-$3');
    if (d.length === 10) return d.replace(/(\d{2})(\d{4})(\d{4})/, '($1) $2-$3');
    return t || '';
  };
  const cpfParcial = (d) => d.replace(/^(\d{3})(\d)/, '$1.$2').replace(/^(\d{3})\.(\d{3})(\d)/, '$1.$2.$3').replace(/^(\d{3})\.(\d{3})\.(\d{3})(\d)/, '$1.$2.$3-$4');
  const telParcial = (d) => (d.length > 10 ? telFmt(d) : d.length > 6 ? `(${d.slice(0, 2)}) ${d.slice(2, 6)}-${d.slice(6)}` : d.length > 2 ? `(${d.slice(0, 2)}) ${d.slice(2)}` : d);
  const momentoBr = (s) => {
    const d = new Date(s.replace(' ', 'T') + 'Z');
    return isNaN(d) ? s : d.toLocaleString('pt-BR');
  };
  const iniciais = (n) => String(n).trim().split(/\s+/).filter(Boolean).slice(0, 2).map((p) => p[0]).join('').toUpperCase();
  const celNome = (n) => el('td', {}, el('div', { class: 'nome-cel' }, el('span', { class: 'avatar' }, iniciais(n)), n));
  const PERFIL = { admin: 'Administrador', dentista: 'Dentista', recepcao: 'Recepção' };
  const podeEditarPacientes = () => eu && ['admin', 'recepcao'].includes(eu.perfil);

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

  // ------------------------------------------------------------ definição das telas
  const CAMPOS = {
    pacientes: [
      { n: 'nome', r: 'Nome completo', req: true, cheio: true, max: 120 },
      { n: 'cpf', r: 'CPF', req: true, mascara: 'cpf', max: 14, inputmode: 'numeric' },
      { n: 'data_nascimento', r: 'Data de nascimento', tipo: 'date' },
      { n: 'telefone', r: 'Telefone', mascara: 'tel', max: 15, inputmode: 'tel' },
      { n: 'email', r: 'E-mail', tipo: 'email', max: 160 },
      { n: 'cidade', r: 'Cidade', max: 80 },
      { n: 'endereco', r: 'Endereço', cheio: true, max: 200 },
      { n: 'observacoes', r: 'Observações', area: true, cheio: true, max: 1000 },
    ],
    funcionarios: [
      { n: 'nome', r: 'Nome completo', req: true, cheio: true, max: 120 },
      { n: 'email', r: 'E-mail (login)', req: true, tipo: 'email', max: 160 },
      { n: 'perfil', r: 'Perfil de acesso', req: true, opcoes: PERFIL },
      { n: 'cargo', r: 'Cargo', max: 80 },
      { n: 'cro', r: 'CRO (dentistas)', max: 20 },
      { n: 'telefone', r: 'Telefone', mascara: 'tel', max: 15, inputmode: 'tel' },
      { n: 'senha', r: 'Senha', tipo: 'password', senha: true, cheio: true, max: 128 },
    ],
  };

  function aplicaMascara(input, tipo) {
    input.addEventListener('input', () => {
      const d = input.value.replace(/\D/g, '');
      input.value = tipo === 'cpf' ? cpfParcial(d.slice(0, 11)) : telParcial(d.slice(0, 11));
    });
  }

  function montaCampos(tipo, valores) {
    const caixa = $('campos');
    caixa.replaceChildren();
    for (const c of CAMPOS[tipo]) {
      const id = 'f-' + c.n;
      let campo;
      if (c.opcoes) {
        campo = el('select', { id, name: c.n, required: c.req });
        for (const [v, rot] of Object.entries(c.opcoes)) campo.append(el('option', { value: v }, rot));
      } else if (c.area) {
        campo = el('textarea', { id, name: c.n, maxlength: c.max });
      } else {
        campo = el('input', {
          id, name: c.n, type: c.tipo || 'text', required: c.req, maxlength: c.max, inputmode: c.inputmode,
          autocomplete: c.senha ? 'new-password' : 'off',
          minlength: c.senha ? 8 : null,
        });
        if (c.mascara) aplicaMascara(campo, c.mascara);
      }
      let v = valores?.[c.n] ?? '';
      if (c.n === 'cpf') v = cpfFmt(v);
      if (c.n === 'telefone') v = telFmt(v);
      if (!c.senha) campo.value = v;
      let rotulo = c.r;
      if (c.senha) rotulo += editando ? ' (deixe em branco para manter)' : ' (mínimo 8 caracteres)';
      const bloco = el('div', { class: 'campo' + (c.cheio ? ' cheio' : '') }, el('label', { for: id }, rotulo + (c.req ? ' *' : '')), campo);
      caixa.append(bloco);
    }
    if (tipo === 'funcionarios' && editando) {
      caixa.append(el('div', { class: 'campo cheio' },
        el('label', { for: 'f-ativo' }, 'Situação'),
        (() => { const s = el('select', { id: 'f-ativo', name: 'ativo' }, el('option', { value: '1' }, 'Ativo'), el('option', { value: '0' }, 'Inativo (sem acesso)')); s.value = String(valores.ativo); return s; })()));
    }
  }

  // ------------------------------------------------------------ listagens
  function tabelaVazia(texto) {
    $('tabela').replaceChildren(el('tbody', {}, el('tr', {}, el('td', { class: 'vazio' }, texto))));
  }
  function monta(cabecalhos, linhas) {
    const t = $('tabela');
    t.replaceChildren(
      el('thead', {}, el('tr', {}, ...cabecalhos.map((h) => el('th', { scope: 'col' }, h)))),
      el('tbody', {}, ...linhas));
  }

  async function carregaPacientes() {
    const q = $('busca').value.trim();
    const lista = await api('/api/pacientes?q=' + encodeURIComponent(q));
    if (!lista.length) return tabelaVazia(q ? 'Nenhum paciente encontrado.' : 'Nenhum paciente cadastrado ainda.');
    monta(['Nome', 'CPF', 'Nascimento', 'Telefone', 'Cidade', ''], lista.map((p) => el('tr', {},
      celNome(p.nome), el('td', {}, cpfFmt(p.cpf)), el('td', {}, dataBr(p.data_nascimento)), el('td', {}, telFmt(p.telefone)), el('td', {}, p.cidade || ''),
      el('td', { class: 'acoes' },
        el('button', { class: 'btn small ghost', type: 'button', onclick: () => abreForm('pacientes', p.id_paciente) }, podeEditarPacientes() ? 'Editar' : 'Ver'),
        eu.perfil === 'admin' ? el('button', { class: 'btn small danger', type: 'button', onclick: () => excluiPaciente(p) }, 'Excluir') : null))));
  }

  async function carregaFuncionarios() {
    const q = $('busca').value.trim().toLowerCase();
    let lista = await api('/api/funcionarios');
    if (q) lista = lista.filter((f) => (f.nome + ' ' + f.email).toLowerCase().includes(q));
    if (!lista.length) return tabelaVazia('Nenhum funcionário encontrado.');
    monta(['Nome', 'E-mail', 'Perfil', 'Cargo / CRO', 'Situação', ''], lista.map((f) => el('tr', {},
      celNome(f.nome), el('td', {}, f.email), el('td', {}, PERFIL[f.perfil]),
      el('td', {}, [f.cargo, f.cro && 'CRO ' + f.cro].filter(Boolean).join(' · ')),
      el('td', {}, el('span', { class: 'tag ' + (f.ativo ? 'ok' : 'off') }, f.ativo ? 'Ativo' : 'Inativo')),
      el('td', { class: 'acoes' }, el('button', { class: 'btn small ghost', type: 'button', onclick: () => abreForm('funcionarios', f.id_funcionario) }, 'Editar')))));
  }

  async function carregaAuditoria() {
    const lista = await api('/api/auditoria');
    if (!lista.length) return tabelaVazia('Sem registros.');
    monta(['Quando', 'Quem', 'Ação', 'Detalhe'], lista.map((l) => el('tr', {},
      el('td', {}, momentoBr(l.momento)), el('td', {}, l.funcionario || '—'), el('td', {}, l.acao), el('td', {}, l.detalhe || ''))));
  }

  async function carregaInteressados() {
    const lista = await api('/api/interesse');
    if (!lista.length) return tabelaVazia('Nenhum pedido de teste grátis ainda.');
    monta(['Quando', 'Nome', 'E-mail', 'Clínica', 'Mensagem'], lista.map((i) => el('tr', {},
      el('td', {}, momentoBr(i.criado_em)), el('td', {}, i.nome), el('td', {}, i.email), el('td', {}, i.clinica || ''), el('td', {}, i.mensagem || ''))));
  }

  async function recarrega() {
    try {
      mensagem('');
      if (aba === 'pacientes') await carregaPacientes();
      else if (aba === 'funcionarios') await carregaFuncionarios();
      else if (aba === 'interessados') await carregaInteressados();
      else await carregaAuditoria();
    } catch (e) { mensagem(e.message); }
  }

  const TITULOS = {
    pacientes: ['Pacientes', 'Cadastre, busque e atualize as fichas dos pacientes.'],
    funcionarios: ['Funcionários', 'Quem tem acesso ao sistema e com qual perfil.'],
    interessados: ['Interessados', 'Pedidos de teste grátis feitos pelo site.'],
    auditoria: ['Auditoria', 'Registro de logins e alterações, escrito pelo sistema.'],
  };

  const CARTAO_ESTAT = (emoji, tom, valor, rotulo) =>
    el('div', { class: 'card sombra' }, el('div', { class: 'emoji ' + tom }, emoji), el('div', {}, el('strong', {}, valor), el('small', {}, rotulo)));

  async function atualizaEstat() {
    const caixa = $('estat');
    caixa.hidden = aba !== 'pacientes';
    if (aba !== 'pacientes') return;
    try {
      const pac = await api('/api/pacientes');
      const semana = Date.now() - 7 * 24 * 3600 * 1000;
      const novos = pac.filter((p) => new Date(p.criado_em.replace(' ', 'T') + 'Z').getTime() > semana).length;
      const cartoes = [CARTAO_ESTAT('🦷', 'tom-azul', pac.length, 'pacientes'), CARTAO_ESTAT('🆕', 'tom-verde', novos, 'novos nos últimos 7 dias')];
      if (eu.perfil === 'admin') {
        const [func, ints] = await Promise.all([api('/api/funcionarios'), api('/api/interesse')]);
        cartoes.push(CARTAO_ESTAT('👥', 'tom-roxo', func.filter((f) => f.ativo).length, 'funcionários ativos'));
        cartoes.push(CARTAO_ESTAT('✉️', 'tom-laranja', ints.length, 'pedidos de teste'));
      }
      caixa.replaceChildren(...cartoes);
    } catch { caixa.hidden = true; }
  }

  function trocaAba(nova) {
    aba = nova;
    document.querySelectorAll('.nav-item').forEach((b) => b.setAttribute('aria-selected', String(b.dataset.aba === nova)));
    $('busca').value = '';
    $('titulo-pagina').textContent = TITULOS[nova][0];
    $('subtitulo-pagina').textContent = TITULOS[nova][1];
    $('ferramentas').hidden = nova === 'auditoria' || nova === 'interessados';
    $('busca').placeholder = nova === 'pacientes' ? 'Buscar por nome, CPF ou e-mail' : 'Buscar por nome ou e-mail';
    const novo = $('btn-novo');
    novo.textContent = nova === 'pacientes' ? '+ Novo paciente' : '+ Novo funcionário';
    novo.hidden = nova === 'auditoria' || nova === 'interessados' || (nova === 'pacientes' && !podeEditarPacientes());
    recarrega();
    atualizaEstat();
  }

  // ------------------------------------------------------------ formulário
  async function abreForm(tipo, id) {
    editando = id ?? null;
    $('form-msg').textContent = '';
    let valores = {};
    try {
      if (id) valores = await api(`/api/${tipo}/${id}`);
    } catch (e) { return mensagem(e.message); }
    const somenteLeitura = tipo === 'pacientes' && !podeEditarPacientes();
    $('dialogo-titulo').textContent = tipo === 'pacientes'
      ? (somenteLeitura ? 'Dados do paciente' : id ? 'Editar paciente' : 'Novo paciente')
      : (id ? 'Editar funcionário' : 'Novo funcionário');
    $('form').dataset.tipo = tipo;
    montaCampos(tipo, valores);
    $('btn-salvar').hidden = somenteLeitura;
    if (somenteLeitura) $('campos').querySelectorAll('input,select,textarea').forEach((c) => (c.disabled = true));
    $('dialogo').showModal();
    $('campos').querySelector('input,select,textarea')?.focus();
  }

  async function salva(ev) {
    ev.preventDefault();
    const tipo = $('form').dataset.tipo;
    const corpo = {};
    $('campos').querySelectorAll('input,select,textarea').forEach((c) => { corpo[c.name] = c.value; });
    if (corpo.ativo !== undefined) corpo.ativo = corpo.ativo === '1';
    const msg = $('form-msg');
    msg.textContent = '';
    $('btn-salvar').disabled = true;
    try {
      await api(editando ? `/api/${tipo}/${editando}` : `/api/${tipo}`, { method: editando ? 'PUT' : 'POST', corpo });
      $('dialogo').close();
      mensagem(editando ? 'Alterações salvas.' : 'Cadastro realizado.', true);
      await (tipo === 'pacientes' ? carregaPacientes() : carregaFuncionarios());
      atualizaEstat();
    } catch (e) { msg.textContent = e.message; }
    finally { $('btn-salvar').disabled = false; }
  }

  async function excluiPaciente(p) {
    if (!confirm(`Excluir o cadastro de ${p.nome}? Esta ação não pode ser desfeita.`)) return;
    try {
      await api('/api/pacientes/' + p.id_paciente, { method: 'DELETE' });
      mensagem('Paciente excluído.', true);
      await carregaPacientes();
      atualizaEstat();
    } catch (e) { mensagem(e.message); }
  }

  // ------------------------------------------------------------ início
  function entra(usuario) {
    eu = usuario;
    $('usuario-nome').textContent = eu.nome;
    $('usuario-perfil').textContent = PERFIL[eu.perfil];
    $('usuario-avatar').textContent = iniciais(eu.nome);
    document.querySelector('[data-aba="funcionarios"]').hidden = eu.perfil !== 'admin';
    document.querySelector('[data-aba="auditoria"]').hidden = eu.perfil !== 'admin';
    document.querySelector('[data-aba="interessados"]').hidden = eu.perfil !== 'admin';
    mostra('app');
    trocaAba('pacientes');
  }

  $('form-login').addEventListener('submit', async (ev) => {
    ev.preventDefault();
    $('login-msg').textContent = '';
    try {
      const u = await api('/api/login', { method: 'POST', corpo: { email: $('login-email').value, senha: $('login-senha').value } });
      $('login-senha').value = '';
      entra(u);
    } catch (e) { $('login-msg').textContent = e.message; }
  });
  $('btn-sair').addEventListener('click', async () => {
    await api('/api/logout', { method: 'POST', corpo: {} }).catch(() => {});
    eu = null;
    mostra('login');
  });
  $('abas').addEventListener('click', (ev) => { const b = ev.target.closest('.nav-item'); if (b) trocaAba(b.dataset.aba); });
  $('btn-novo').addEventListener('click', () => abreForm(aba));
  $('btn-cancelar').addEventListener('click', () => $('dialogo').close());
  $('form').addEventListener('submit', salva);
  let espera;
  $('busca').addEventListener('input', () => { clearTimeout(espera); espera = setTimeout(recarrega, 250); });

  api('/api/me').then(entra).catch(() => mostra('login'));
})();
