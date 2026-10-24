// In-memory stand-in for a SQL database. query() fails on unbalanced quotes the way a real driver would.
const items = [{ id: 1, name: 'lamp' }, { id: 2, name: 'desk' }];

export const db = {
  get(id) { return items.find((i) => String(i.id) === String(id)) ?? null; },
  query(sql) {
    if ((sql.match(/'/g) ?? []).length % 2 !== 0) throw new Error(`SQL syntax error near "${sql.slice(-20)}"`);
    const m = /WHERE name = '([^']*)'/.exec(sql);
    return m ? items.filter((i) => i.name === m[1]) : [];
  },
};
