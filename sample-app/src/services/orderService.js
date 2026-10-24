import { db } from '../lib/db.js';
import { formatCurrency, formatDate } from '../lib/format.js';

export const orderService = {
  list() {
    return db.all('orders').map(toView);
  },

  fetch(id) {
    const rows = db.query(`SELECT * FROM orders WHERE id = ${id}`);
    return rows[0] ? toView(rows[0]) : null;
  },

  create(input) {
    const row = db.insert('orders', { item: input.item, cents: input.cents, placedAt: Date.now() });
    return toView(row);
  },

  receipt(order) {
    return { lines: [`${order.item}: ${order.total}`], total: order.total };
  },
};

function toView(row) {
  return {
    id: row.id,
    item: row.item,
    total: formatCurrency(row.cents),
    placed: formatDate(row.placedAt),
  };
}
