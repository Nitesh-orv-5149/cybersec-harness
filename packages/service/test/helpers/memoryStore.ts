// In-memory stand-in for the MongoDB Store, implementing only the collection operations the web-scan service
// uses (findOne/find with sort/limit/projection, insertOne/insertMany, updateOne with $set/$setOnInsert/upsert).
// It lets the finding lifecycle be tested without a MongoDB server. It is NOT a MongoDB emulator: the real
// persistence path is covered by web-nuclei.integration.test.ts against a real server.
type Doc = Record<string, any>;

const get = (d: Doc, k: string) => k.split('.').reduce<any>((o, p) => (o == null ? undefined : o[p]), d);
function set(d: Doc, k: string, v: unknown) {
  const parts = k.split('.');
  let o = d;
  for (const p of parts.slice(0, -1)) o = (o[p] ??= {});
  o[parts.at(-1)!] = v;
}

function matches(d: Doc, q: Doc): boolean {
  return Object.entries(q).every(([k, cond]) => {
    const v = get(d, k);
    if (cond instanceof RegExp) return typeof v === 'string' && cond.test(v);
    if (cond && typeof cond === 'object' && !Array.isArray(cond) && !(cond instanceof Date)) {
      return Object.entries(cond).every(([op, x]) => {
        if (op === '$ne') return v !== x;
        if (op === '$in') return (x as unknown[]).some((y) => (Array.isArray(v) ? v.includes(y) : v === y));
        if (op === '$regex') return typeof v === 'string' && new RegExp(x as RegExp).test(v);
        throw new Error(`memoryStore: unsupported operator ${op}`);
      });
    }
    return Array.isArray(v) ? v.includes(cond) : v === cond;
  });
}

class Cursor {
  constructor(private docs: Doc[]) {}
  sort(s: Doc) {
    const [[k, dir]] = Object.entries(s) as [string, number][];
    this.docs.sort((a, b) => (get(a, k) > get(b, k) ? dir : get(a, k) < get(b, k) ? -dir : 0));
    return this;
  }
  limit(n: number) { this.docs = this.docs.slice(0, n); return this; }
  async next() { return structuredClone(this.docs[0] ?? null); }
  async toArray() { return structuredClone(this.docs); }
}

export class MemoryCollection {
  docs: Doc[] = [];
  find(q: Doc = {}) { return new Cursor(this.docs.filter((d) => matches(d, q))); }
  async findOne(q: Doc, opts: { sort?: Doc } = {}) {
    const c = this.find(q);
    if (opts.sort) c.sort(opts.sort);
    return (await c.limit(1).toArray())[0] ?? null;
  }
  async insertOne(d: Doc) {
    if (this.docs.some((x) => x._id === d._id)) throw Object.assign(new Error('E11000 duplicate key'), { code: 11000 });
    this.docs.push(structuredClone(d));
    return { insertedId: d._id };
  }
  async insertMany(ds: Doc[]) {
    let dup = false;
    for (const d of ds) { try { await this.insertOne(d); } catch { dup = true; } }
    if (dup) throw Object.assign(new Error('E11000 duplicate key'), { code: 11000 });
  }
  async updateOne(q: Doc, u: Doc, opts: { upsert?: boolean } = {}) {
    let d = this.docs.find((x) => matches(x, q));
    const inserted = !d;
    if (!d) {
      if (!opts.upsert) return { matchedCount: 0 };
      // Like MongoDB: an upsert inserts the equality fields of the filter, and a clashing _id is a duplicate key error.
      d = Object.fromEntries(Object.entries(q).filter(([, v]) => v === null || typeof v !== 'object' || v instanceof Date));
      const id = u.$setOnInsert?._id ?? d._id;
      if (id !== undefined && this.docs.some((x) => x._id === id)) throw Object.assign(new Error(`E11000 duplicate key error dup key: { _id: "${id}" }`), { code: 11000 });
      this.docs.push(d);
    }
    for (const [k, v] of Object.entries(u.$set ?? {})) set(d, k, structuredClone(v));
    for (const [k, v] of Object.entries(u.$inc ?? {})) set(d, k, (get(d, k) ?? 0) + (v as number));
    for (const [k, v] of Object.entries(u.$addToSet ?? {})) {
      const cur = (get(d, k) as unknown[] | undefined) ?? [];
      const add = v && typeof v === 'object' && '$each' in (v as Doc) ? (v as Doc).$each : [v];
      set(d, k, [...cur, ...add.filter((x: unknown) => !cur.includes(x))]);
    }
    if (inserted) for (const [k, v] of Object.entries(u.$setOnInsert ?? {})) set(d, k, structuredClone(v));
    return { matchedCount: inserted ? 0 : 1 };
  }
  async findOneAndUpdate(q: Doc, u: Doc, opts: { upsert?: boolean } = {}) {
    await this.updateOne(q, u, opts);
    return this.findOne(q);
  }
  async updateMany(q: Doc, u: Doc) {
    const ids = this.docs.filter((x) => matches(x, q)).map((x) => x._id);
    for (const id of ids) await this.updateOne({ _id: id }, u);
    return { matchedCount: ids.length };
  }
  async deleteOne(q: Doc) {
    const i = this.docs.findIndex((x) => matches(x, q));
    if (i >= 0) this.docs.splice(i, 1);
    return { deletedCount: i >= 0 ? 1 : 0 };
  }
}

export class MemoryStore {
  available = true;
  lastError: string | null = null;
  readonly cols = new Map<string, MemoryCollection>();
  col(name: string) {
    if (!this.cols.has(name)) this.cols.set(name, new MemoryCollection());
    return this.cols.get(name)! as any;
  }
}
