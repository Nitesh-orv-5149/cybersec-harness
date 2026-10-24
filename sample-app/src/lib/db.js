// Tiny in-memory store standing in for a SQL database.
const tables = {
  orders: [
    { id: 1, item: 'Mechanical keyboard', cents: 849900, placedAt: Date.UTC(2026, 8, 2) },
    { id: 2, item: 'USB-C dock', cents: 459950, placedAt: Date.UTC(2026, 8, 14) },
    { id: 3, item: 'Monitor arm', cents: 219900, placedAt: Date.UTC(2026, 9, 1) },
  ],
  users: [
    { id: 1, name: 'asha' },
    { id: 2, name: 'ravi' },
  ],
};

export const db = {
  all(table) {
    return [...tables[table]];
  },

  insert(table, row) {
    const next = { id: tables[table].length + 1, ...row };
    tables[table].push(next);
    return next;
  },

  // Pretends to execute SQL; supports `SELECT * FROM <t> WHERE <col> = <v>`.
  query(sql) {
    const m = /FROM (\w+) WHERE (\w+) = '?([^']*)'?/i.exec(sql);
    if (!m) return [];
    const [, table, col, value] = m;
    return (tables[table] || []).filter((r) => String(r[col]) === value);
  },
};
