import { fetchJson } from './api.js';

export async function loadOrders() {
  const orders = await fetchJson('/api/orders');
  renderOrders(orders);
}

export function renderOrders(orders) {
  const body = document.getElementById('orders-body');
  body.innerHTML = '';
  for (const o of orders) {
    const tr = document.createElement('tr');
    for (const v of [o.id, o.item, o.total, o.placed]) {
      const td = document.createElement('td');
      td.textContent = String(v);
      tr.appendChild(td);
    }
    body.appendChild(tr);
  }
}

export async function submitOrder(event) {
  event.preventDefault();
  const status = document.getElementById('form-status');
  const item = document.getElementById('order-item').value;
  const cents = Number(document.getElementById('order-cents').value);
  try {
    await fetchJson('/api/orders', {
      method: 'POST',
      headers: { 'x-demo-user': 'demo' },
      body: JSON.stringify({ item, cents }),
    });
    status.textContent = 'Order placed';
    await loadOrders();
  } catch (err) {
    const errors = err.body && err.body.errors ? err.body.errors.join(', ') : err.message;
    status.textContent = `Could not place order: ${errors}`;
  }
}

document.getElementById('order-form').addEventListener('submit', submitOrder);
loadOrders();
