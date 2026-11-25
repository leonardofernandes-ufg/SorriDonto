(() => {
  const btn = document.getElementById('menu-btn');
  const menu = document.getElementById('menu');
  btn.addEventListener('click', () => {
    const aberto = menu.classList.toggle('aberto');
    btn.setAttribute('aria-expanded', String(aberto));
  });
  menu.addEventListener('click', (e) => {
    if (e.target.closest('a')) { menu.classList.remove('aberto'); btn.setAttribute('aria-expanded', 'false'); }
  });
  document.getElementById('ano').textContent = new Date().getFullYear();

  const form = document.getElementById('form-interesse');
  const msg = document.getElementById('interesse-msg');
  form.addEventListener('submit', async (ev) => {
    ev.preventDefault();
    msg.className = 'msg';
    msg.textContent = '';
    const corpo = Object.fromEntries(new FormData(form));
    try {
      const r = await fetch('/api/interesse', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(corpo) });
      const d = await r.json().catch(() => ({}));
      if (!r.ok) throw new Error(d.erro || 'Não foi possível enviar agora.');
      form.reset();
      msg.className = 'msg ok';
      msg.textContent = 'Recebemos o seu pedido! Em breve entraremos em contato.';
    } catch (e) { msg.textContent = e.message; }
  });
})();
