// Demo helper: apply or revert a deliberate regression in the fixture app.
// usage: node demo/regression.mjs <menu|currency|layout> <apply|revert>
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const regressions = {
  menu: {
    file: 'public/js/nav.js',
    good: "nav.classList.toggle('is-open')",
    bad: "nav.classList.toggle('open')",
  },
  currency: {
    file: 'src/lib/format.js',
    good: 'return `₹${(cents / 100).toFixed(2)}`;',
    bad: 'return `Rs ${Math.round(cents / 100)}`;',
  },
  layout: {
    file: 'public/css/site.css',
    good: '.primary-action { display: inline-block;',
    bad: '.primary-action { min-width: 520px; display: inline-block;',
  },
};

const [name, action] = process.argv.slice(2);
const r = regressions[name];
if (!r || !['apply', 'revert'].includes(action)) {
  console.error('usage: node demo/regression.mjs <menu|currency|layout> <apply|revert>');
  process.exit(2);
}
const p = path.join(root, r.file);
const text = fs.readFileSync(p, 'utf8');
const [from, to] = action === 'apply' ? [r.good, r.bad] : [r.bad, r.good];
if (!text.includes(from)) {
  console.log(`${name}: already ${action === 'apply' ? 'applied' : 'reverted'} (${r.file})`);
  process.exit(0);
}
fs.writeFileSync(p, text.replace(from, to));
console.log(`${name}: ${action} -> ${r.file}`);
