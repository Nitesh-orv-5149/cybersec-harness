export function initNav() {
  const toggle = document.getElementById('menu-toggle');
  const nav = document.getElementById('site-nav');
  if (!toggle || !nav) return;
  toggle.addEventListener('click', () => toggleMenu(toggle, nav));
}

export function toggleMenu(toggle, nav) {
  const open = nav.classList.toggle('is-open');
  toggle.setAttribute('aria-expanded', String(open));
}

initNav();
