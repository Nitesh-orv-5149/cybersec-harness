# Dependency-scanner fixtures

| File | Provenance |
|---|---|
| `npm-vulnerable/` | Test project whose `package-lock.json` was generated with `npm install --package-lock-only --ignore-scripts` (npm 10.9.9). Pins `express@4.17.1`, `lodash@4.17.20`, dev `minimist@1.2.5`. Nothing is installed or executed. |
| `npm-audit.vulnerable.real.json` | **Real** output of `npm audit --json --package-lock-only` (npm 10.9.9, 2026-10-24) run in `npm-vulnerable/`. Advisory data reflects the registry on that date. |
| `npm-audit.clean.real.json` | **Real** output of the same command in `sample-app/` (no advisories). |
| `npm-audit.enolock.real.json` | **Real** stdout of the same command in a folder with `package.json` but no lockfile (ENOLOCK). |
| `osv-scanner.synthetic.json` | **Synthetic.** Hand-written from the documented osv-scanner JSON layout and the OSV schema. osv-scanner could not be installed in the development environment. |
| `trivy.synthetic.json` | **Synthetic.** Hand-written from the documented Trivy JSON report layout. Trivy could not be installed in the development environment. |

Replace the synthetic files with real tool output once those tools are available, and keep the names explicit (`*.real.json` / `*.synthetic.json`).
