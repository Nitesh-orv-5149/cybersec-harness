// Build step: copy public/ into dist/public and stamp a build id.
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';

const root = path.dirname(new URL(import.meta.url).pathname);
const src = path.join(root, 'public');
const out = path.join(root, 'dist', 'public');

fs.rmSync(path.join(root, 'dist'), { recursive: true, force: true });
fs.cpSync(src, out, { recursive: true });

const hash = crypto.createHash('sha256');
for (const f of fs.readdirSync(src, { recursive: true }).sort()) {
  const p = path.join(src, String(f));
  if (fs.statSync(p).isFile()) hash.update(String(f)).update(fs.readFileSync(p));
}
fs.writeFileSync(path.join(out, 'build-info.json'), JSON.stringify({ build: hash.digest('hex').slice(0, 12) }));
console.log('built dist/public');
