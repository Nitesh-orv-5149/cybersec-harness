import { db } from '../lib/db.js';

export function listUsers() {
  return db.all('users').map((u) => ({ id: u.id, name: u.name }));
}

export function findUserByName(name) {
  const clean = name.replace(/[^a-z0-9 ]/gi, '');
  return db.query(`SELECT * FROM users WHERE name = '${clean}'`);
}
