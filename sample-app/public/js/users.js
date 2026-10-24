import { fetchJson } from './api.js';

export async function loadUsers() {
  const users = await fetchJson('/api/users');
  const list = document.getElementById('users-list');
  list.innerHTML = '';
  for (const u of users) {
    const li = document.createElement('li');
    li.textContent = u.name;
    list.appendChild(li);
  }
}

loadUsers();
