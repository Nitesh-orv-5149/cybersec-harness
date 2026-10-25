# Code impact workbench (working name)

A local developer tool that watches your project while you work, builds a dependency graph from the source (endpoints → handlers → services → database ops → sensitive sinks, plus client code and tests), shows what a change can affect, and checks what actually happens in the running website by building a baseline and a current snapshot side by side and driving both with a real browser. History lives in MongoDB.

No Git integration, no commits required, no remote LLM.

```
editor events ──► VS Code extension ──┐
filesystem events ──► chokidar ───────┼─► local service (Node/TS, 127.0.0.1:4317)
                                      │      ├─ analyzer: TypeScript compiler API → per-file facts → linker → graph
                                      │      ├─ debounce/coalesce queue → incremental re-parse → graph diff → impact
                                      │      ├─ snapshots (content-addressed copies, outside your working tree)
                                      │      ├─ runner (approved build/start commands, process groups, timeouts)
                                      │      ├─ Playwright scenarios → pixelmatch diff → classification
                                      │      ├─ findings: deterministic rules + runtime↔graph correlation
                                      │      └─ MongoDB (10 collections, aggregation pipelines)
                                      └─► dashboard (React + Cytoscape/dagre), live over WebSocket
```

## Quick start

Requirements: Node 20+, MongoDB 6+ (local or Atlas), Chromium for Playwright.

```sh
# MongoDB (pick one)
docker run -d --name wb-mongo -p 27017:27017 mongo:8          # or podman
# Arch: yay -S mongodb-bin && sudo systemctl start mongodb

npm install
npx playwright install chromium
(cd sample-app && npm install)
npm run build
npm start -- --project ./sample-app
# open http://127.0.0.1:4317
```

Options: `--port`, `--mongo <uri>`, `--db <name>`, `--no-monitor`, repeat `--project` for several folders. Env: `WORKBENCH_MONGO_URI`, `WORKBENCH_DATA_DIR` (snapshots/screenshots, default `~/.local/share/workbench`), `WORKBENCH_LOG_LEVEL`.

> Using MongoDB Atlas (or any non-default URI) from a `.env` file? The CLI does not auto-load `.env`, so start it with Node's own loader:
> ```sh
> node --env-file=.env packages/service/dist/cli.js --project ./sample-app
> ```
> `.env` holds `WORKBENCH_MONGO_URI` and `WORKBENCH_MONGO_DB`. Without a reachable MongoDB the live graph still updates, but history, findings, dependency scans and the AI-agent log are disabled.

### VS Code extension

```sh
cd packages/extension && npm run build
# then either open this folder in VS Code and press F5, or: npx @vscode/vsce package && code --install-extension *.vsix
```

Commands: *Start monitoring this workspace*, *Open dashboard*, *Mark current files as baseline*, *Compare current files with baseline*, *Re-analyse*, *Full rescan*. The status bar shows analysis/website state. Unsaved buffers are sent (debounced) for analysis only; the graph marks them with a dashed outline and website runs never include them. "Open in editor" in the dashboard jumps to the source location.

### LLM orchestrator (the AI agent)

`packages/orchestrator` is a small Python agent that watches the harness's live graph over the WebSocket and, when a code change touches an endpoint, decides which security tools to run against it. It does not run scanners itself: it asks the harness to run the **real** dependency scanners (npm audit, OSV-Scanner, OSV.dev API, Trivy) so results land in the same MongoDB and dashboard as everything else. It also runs three lightweight endpoint probes (`auth_probe`, `sqli_probe`, `secret_scan`) directly against the running app. Every step — the change it noticed, the tools it chose (and whether the model or the fallback chose them), and each result — is reported to the harness and shown live in the dashboard's **AI agent** tab.

```sh
# 1. the harness and the app it monitors must be running first
node --env-file=.env packages/service/dist/cli.js --project ./sample-app   # terminal 1
(cd sample-app && node src/server.js)                                      # terminal 2 (the app under test, on :3000)

# 2. (optional) a local model for the tool-choice step — without it the agent safely falls back to running every available tool
#    install Ollama, then:  ollama pull qwen3:4b-instruct-2507-q8_0

# 3. the agent
python3 -m venv packages/orchestrator/.venv
packages/orchestrator/.venv/bin/pip install -r packages/orchestrator/requirements.txt
packages/orchestrator/.venv/bin/python packages/orchestrator/main.py                 # terminal 3
```

Now edit a watched route (e.g. append a line to `sample-app/src/routes/orders.js`): within ~1s the harness re-analyses, the agent wakes, picks tools, runs them, and the **AI agent** dashboard tab fills with its decisions and findings. The agent only offers the model scanners the harness currently reports as *ready* (installed and reachable), so it can never pick a tool that isn't usable. Dependency scans are project-wide, so the agent runs them once per change batch rather than once per endpoint.

Config: the harness and app URLs and the Ollama model live at the top of `packages/orchestrator/harness.py` and `llm.py`. The agent's own copy of findings is a flat `packages/orchestrator/memory.json` (a stand-in for a Mongo collection); the authoritative scan runs are persisted by the harness.

## macOS setup (step by step)

**Prerequisites:** Homebrew, Node.js 20+ (22 recommended: `brew install node@22`), Python 3 with `pipx` (`brew install pipx && pipx ensurepath`), MongoDB.

```sh
# 1. MongoDB
brew tap mongodb/brew && brew install mongodb-community
brew services start mongodb-community          # listens on mongodb://127.0.0.1:27017

# 2. the workbench
unzip security-workbench-merged.zip && cd security-workbench-merged
npm install
npx playwright install chromium                 # browser for Website comparison
(cd sample-app && npm install)                  # the demo app
npm run build                                   # dashboard, service and extension
cp .env.example .env                            # optional; only needed for a non-default MongoDB
node --env-file=.env packages/service/dist/cli.js --project ./sample-app    # or without --env-file for defaults
# open http://127.0.0.1:4317
```

**Scanners (all optional; the workbench never installs or updates them).** A missing tool shows as `not installed` and its runs are stored as `unavailable` with no counts, never as a clean result.

| Tool | Install on macOS | Used by |
|---|---|---|
| npm audit | comes with npm | Dependency scan |
| OSV.dev API | no install; needs `security.allowNetwork: true` | Dependency scan |
| OSV-Scanner | `brew install osv-scanner` | Dependency scan |
| Trivy | `brew install trivy` | Dependency scan |
| Schemathesis 4.x | `pipx install schemathesis` | Security tools → API testing |
| Gitleaks 8.19+ | `brew install gitleaks` | Security tools → Secrets detection |
| Checkov 3.x | `pipx install checkov` (or `brew install checkov`) | Security tools → Infrastructure checks |
| Nuclei 3.x | `brew install nuclei`, then once: `nuclei -ut` to download templates yourself | Security tools → Web scanning, Website comparison → Security changes |
| Ollama (optional) | `brew install ollama && ollama pull qwen3:4b-instruct-2507-q8_0` | AI agent tool choice |

**Availability check:** open **Security tools** and press **Re-check tools**, and **Dependency scan** for the dependency scanners. Each tool shows its state, version and executable. If a pipx-installed tool shows "its interpreter ... does not exist", Homebrew replaced the Python it was built on: run `pipx reinstall <tool>`.

**Safe scan execution**
- Static scans (dependencies, Gitleaks, Checkov) only read files; Checkov runs offline.
- API testing needs `security.api.allowActiveTesting: true`, approved run commands (Website comparison → Approve run commands) and a ticked confirmation per run. It only targets a disposable local copy the workbench starts itself.
- Nuclei needs an explicit confirmation per scan, targets loopback or `security.nuclei.authorizedTargets` only, uses only vetted local templates (no intrusive, fuzzing, brute-force, OAST or state-changing templates by default) and never downloads templates during a scan.

**Troubleshooting**
- *"Dashboard not built"*: run `npm run build`.
- *MongoDB unavailable*: `brew services list`; the graph still updates, but scans and history need MongoDB.
- *A browser scenario was skipped*: the banner names the unsupported step; the rest of `workbench.config.json` still applies.
- *Managed target did not start*: the run shows the app log. Check `run.start`, `run.healthPath`, `run.startTimeoutMs`, and that `snapshot.exclude` does not drop files the app needs (for example a built `dist` folder; see the Juice Shop example).
- *Port 4317 in use*: `WORKBENCH_PORT=4318 node packages/service/dist/cli.js --project ...`.
## Demo walkthrough (sample app)

The sample app is a labelled fixture: an Express orders API with a static frontend, three node:test tests, and deliberately unsafe endpoints.

1. **Open a workspace.** `npm start -- --project ./sample-app`. The graph shows 10 endpoints (with router mount prefixes resolved), 28 functions, 3 DB ops, 5 sensitive sinks, 3 tests.
2. **Inspect the graph.** Search `formatCurrency`, click it: four endpoints, two client functions and two tests depend on it. Reachability tab: `GET /api/orders/:id › getOrder › orderService.fetch › db.query()` (dynamic SQL, no auth observed, high).
3. **Change code without committing.** `node sample-app/demo/regression.mjs currency apply`. Within ~1s the graph version bumps, `formatCurrency` pulses orange, the impact panel lists affected endpoints and dependency paths, a `file_events` row is written.
4. **Observe the website.** Website comparison tab: mark baseline (do this before step 3), approve the run commands once, run a comparison. Also apply `menu` (`regression.mjs menu apply`). Result: 3 confirmed regressions (mobile menu, rupee totals ×2) with baseline/current/diff screenshots, failing assertions, and findings linking each failure to the changed code through the requests the page actually made.
5. **Fix and verify.** `regression.mjs currency revert` and `menu revert`, run again: all scenarios unchanged, the 5 runtime findings flip to resolved with `verified_fixed` records; the failed run stays in history.
6. **Demonstrate a failure.** Add a bad import to `sample-app/src/server.js` and run: status `failed`, "candidate start failed … No browser result reflects the current source", start log shown, no findings resolved. Change a command in `workbench.config.json`: approval is revoked until re-approved. Stop MongoDB: the graph keeps updating, the dashboard says history and verification are paused, APIs return 503.
7. **History.** History tab: file events (with dedupe counts), snapshots, analysis runs, browser runs, verification records, plus the scenario pass/fail aggregation and findings summary pipelines.

## Configuration (`workbench.config.json` in the project root)

```jsonc
{
  "analysis": { "include": ["src", "public/js", "tests"], "exclude": [] },
  "snapshot": { "exclude": ["node_modules", "dist", ".git"], "linkNodeModules": true },
  "run": {                                   // required for website verification; must be approved in the dashboard
    "build": "npm run build", "start": "node src/server.js",
    "portEnv": "PORT", "healthPath": "/health", "buildTimeoutMs": 60000, "startTimeoutMs": 20000, "env": {}
  },
  "staticMap": { "/": "public" },            // URL prefix → source dir; marks client code and maps loaded assets back to files
  "browser": {
    "viewports": [{ "name": "desktop", "width": 1280, "height": 800 }, { "name": "mobile", "width": 390, "height": 844 }],
    "diffThreshold": 0.001, "pixelThreshold": 0.1, "mask": [".timestamp"],
    "scenarios": [{ "id": "home", "name": "Home loads", "path": "/", "viewports": ["mobile"], "steps": [
      { "click": "#menu-toggle" }, { "expectVisible": "#nav" }, { "expectNoHorizontalOverflow": true }
    ] }]
  },
  "verification": { "trigger": "manual", "debounceMs": 400 }   // "on-save" re-runs after saved changes
}
```

Steps: `click`, `fill`, `press`, `waitFor`, `goto`, `expectVisible`, `expectHidden`, `expectText`, `expectNoHorizontalOverflow`, `expectStatus`. Routes are never invented; only configured scenarios run.

## Dependency vulnerability scanning

The **Dependency scan** tab runs external scanners against the project's npm lockfile and stores the results in MongoDB next to the other findings. The workbench never downloads or installs a scanner: it only uses tools it finds on `PATH` (or at a configured path) and shows which ones are usable.

| Tool | What it checks | Needs network | Install (Arch) |
|---|---|---|---|
| OSV.dev (web API) | `package-lock.json` package names and versions, sent to the public OSV API. **Nothing to install.** | `api.osv.dev` | https://google.github.io/osv.dev/api/ |
| OSV-Scanner | `package-lock.json` against the OSV database | `api.osv.dev` (unless `osvOffline`) | see https://google.github.io/osv-scanner/ |
| npm audit | `package-lock.json` / `npm-shrinkwrap.json` via the registry's bulk advisory endpoint | the npm registry | ships with npm |
| Trivy | `trivy fs --scanners vuln`, ingesting the root `package-lock.json` result | DB download from mirror.gcr.io / ghcr.io (unless `trivyOffline`) | `pacman -S trivy` (check `pacman -Si trivy`) |

```jsonc
"security": {
  "allowNetwork": false,                    // tools that contact a remote service run only when true
  "dependencies": {
    "mode": "first-available",              // or "all-available" to cross-check with every ready tool
    "order": ["osv-api", "npm-audit", "osv-scanner", "trivy"],
    "fallbackOnFailure": true,              // try the next ready tool if one fails or times out
    "includeDev": true,                     // npm audit --omit=dev when false
    "timeoutMs": 180000, "maxOutputBytes": 33554432,
    "binaries": { "trivy": "/usr/bin/trivy" },   // optional explicit paths
    "osvOffline": false, "trivyOffline": false
  }
}
```

**How results are reported**
- Each tool is run with an argument array, no shell, a timeout that kills its process group, and bounded output.
- Every run records, for each tool, whether it was `completed`, `failed`, `timed_out`, `inconclusive`, `unavailable` (with the reason, such as "not installed" or "needs network permission") or `skipped` (with the reason, such as "already covered by npm audit").
- Each lockfile gets a coverage status: `covered`, `partial`, `failed` or `unavailable`. A run with no covered lockfile has **no counts at all**, never "0 vulnerabilities".
- Exit codes are not trusted on their own. npm audit exits 1 when it finds advisories. OSV-Scanner uses 0/1 for results, 127 for an error and 128 for "no packages". Trivy runs with `--exit-code 0`. The report always decides the outcome.

**Severity:** `critical` and `high` map to high, `moderate`/`medium` to medium, `low` to low and `info` to info. If no severity was supplied, it stays `unknown`. The workbench scale has no critical level, so the published label (for example "critical") is stored and shown next to the mapped value.

**Deduplication:** two reports are merged into one finding only when they concern the same package and installed version and share an advisory id that a tool supplied (primary id or alias). Each tool's observation is kept separately in `security_observations`. npm audit reports GHSA ids only, and no CVE is inferred for it.

**Lifecycle:**
- A finding is `resolved` only when the vulnerable version is no longer in the lockfile.
- It becomes `not_currently_observed` only when a tool that reported it earlier completed again and the version is unchanged.
- If it is reported again after that, it is flagged as a potential regression.
- A failed or unavailable scan changes nothing.

**Package use:** each finding states how the package is used, based on the existing code graph:
- `called_from_analysed_code`: a call through the imported binding was resolved. The finding links to the calling functions and the endpoints that reach them.
- `imported_by_analysed_code`
- `declared_not_imported`
- `transitive`: the finding names the direct dependency that pulls the package in.
- `not_in_lockfile`

None of these shows that the vulnerable function itself is called.

Fixture provenance (real vs synthetic reports) is listed in `packages/service/test/fixtures/deps/README.md`.

## Security tools (API testing, web scanning, source code, secrets, infrastructure)

The **Security tools** tab groups the other scanners by what they examine. Each category has its own panel with the following:
- tool availability: status, version, executable and the hosts it contacts
- a Run button, with an authorisation step for modes that send attack-style traffic
- the latest run: coverage, per-tool status, exit code, duration, number of findings and the raw report
- open findings
- run history

| Category | Tool | What it examines | Finding source |
|---|---|---|---|
| API testing | Schemathesis | a running local copy of the app, driven by an OpenAPI schema | `api` |
| Secrets detection | Gitleaks | project files (workspace mode) or every commit (history mode) | `secrets` |
| Web scanning | Nuclei | a running copy of the app (or an authorised URL), or the baseline and current snapshots side by side | `web` |
| Infrastructure checks | Checkov | Terraform, CloudFormation, Kubernetes, Helm, Kustomize, Dockerfiles, CI pipeline files, Serverless, ARM/Bicep | `iac` |

Not integrated: OWASP ZAP, Syft/Grype and Semgrep (see Limitations). Nuclei has its own service because it can compare two snapshots; it is listed in **Security tools → Web scanning** and also shown in **Website comparison → Security changes** (same scans, same history).

Rules shared by every category:
- A run without a usable tool is `unavailable`, and one whose tool failed is `failed`. A category with nothing to scan is `not_applicable`. None of these has counts, so none of them can read as "0 issues".
- Each tool's result is stored as an immutable observation in `security_observations`, with the tool's own rule id, severity label, confidence and evidence. Findings in `graph_findings` merge observations with the same location and rule, and list every scanner that reported them.
- Findings are linked to the code graph only by structure. A request path that matches a route links to its endpoint, handler and the sensitive calls it reaches. A `file:line` links to the function that contains it and the endpoints above it. A link is never presented as proof of exploitability.
- A finding becomes `not_currently_observed` only when a tool that reported it ran to completion again and covered its location. Nothing is automatically marked `resolved`, and a finding reported again is flagged as a potential regression.

### API testing (Schemathesis)

Install it yourself, for example `pipx install schemathesis` (version 4.x, MIT licence). The workbench looks for `schemathesis` or `st` on `PATH`, or uses `security.api.binary`.

```jsonc
"security": {
  "api": {
    "allowActiveTesting": false,        // must be true before anything is sent; each run is also confirmed in the dashboard
    "schema": { "source": "auto", "path": "openapi.json" },  // auto: this file if set, else derived from the code graph
    "methods": ["GET", "HEAD", "OPTIONS"],   // add POST/PUT/PATCH/DELETE explicitly to test state-changing operations
    "checks": ["not_a_server_error"],        // any Schemathesis check name
    "phases": ["examples", "coverage", "fuzzing"],
    "maxExamples": 30, "requestTimeoutSec": 5, "workers": 1, "rateLimit": "20/s", "seed": 7,
    "headers": { "Authorization": "Bearer <test-account token>" },  // values are redacted in stored evidence
    "timeoutMs": 600000
  }
}
```

**Target.** The only target is a local copy that the workbench snapshots from your workspace and starts on `127.0.0.1` with the approved `run` commands. You can't enter arbitrary URLs. Proxy variables are removed from the tool's environment.

**Schema.** Without a schema file, the workbench builds OpenAPI 3.0 from the Express routes in the code graph:
- Path parameters come from the route template, and query and body fields from what each handler reads directly (`req.query.x`, `const { id } = req.params`, `req.body`).
- String inputs carry a few boundary examples (`''`, `'`, `"`, `0`, `-1`) for the examples phase.
- Types and response contracts are unknown, so mostly server errors are detected.
- Each operation keeps an `x-workbench-endpoint` link back to its graph node.

**Results.** Schemathesis writes its JSON run report and NDJSON event stream to the run folder; both are stored as raw reports. Each failing check becomes one observation with the following:
- the check name and code (for example `not_a_server_error` / `ST101`)
- Schemathesis' own severity label
- the first failing request and its response, with secret headers and query tokens redacted, plus an occurrence count

Operations that Schemathesis tested and that no longer fail move their findings to `not_currently_observed`.

### Example: OWASP Juice Shop

`examples/juice-shop.workbench.config.json` is a working starting point. Copy it to the Juice Shop root as `workbench.config.json` after `npm install` has built the frontend and server. Three things differ from the defaults:
- **Snapshot.** The default `snapshot.exclude` contains `dist`, which matches every folder of that name. Juice Shop refuses to start without `frontend/dist/frontend/index.html`, so the example excludes the frontend sources and caches instead, and raises `maxFiles` / `maxBytes`.
- **Start.** `npm run build:server` compiles the server in the disposable copy, `node build/app` starts it with `PORT` set, and startup gets 3 minutes (Juice Shop seeds its database first).
- **API testing.** `GET` and `POST` are both enabled. The copy is thrown away after the run, so state changes don't touch your workspace. The code graph resolves Juice Shop's handler factories (`app.get(path, asyncHandler(searchProducts()))`), so `GET /rest/products/search` gets boundary examples for `q` and links to its `sequelize.query` call.

If a browser scenario in your config uses an unsupported step, only that scenario is skipped (with a banner naming the step). The run commands and security settings still apply.

### Secrets detection (Gitleaks)

Install it yourself (`brew install gitleaks`, `pacman -S gitleaks`, or a release binary; 8.19 or newer, MIT licence). The workbench looks for `gitleaks` on `PATH`, or uses `security.secrets.binary`. Nothing is sent anywhere and no app is started, so no authorisation step is needed.

```jsonc
"security": {
  "secrets": {
    "exclude": ["dist", "build", "coverage", ".next", ".workbench"],  // on top of Gitleaks' own allowlist (node_modules, lockfiles, binaries)
    "maxTargetMegabytes": 10,
    "timeoutMs": 300000
  }
}
```

- **Modes.** `workspace` runs `gitleaks dir` on the files as they are now. `history` runs `gitleaks git` on every commit and needs the project folder to be the repository root. Each mode only re-checks its own findings: a workspace run never marks a history finding as gone, and the reverse.
- **Rules.** Gitleaks' default rules, or your `.gitleaks.toml` when the project has one (the generated config extends it). `.gitleaksignore` fingerprints and `gitleaks:allow` comments are honoured.
- **Secret values are never stored.** Gitleaks runs with `--redact`, the raw report is deleted after reading, and only a sanitised copy is kept (author e-mails removed). If a value ever came back unredacted it would be withheld and the run notes would say so.
- **Results.** Exit code 42 means leaks, 0 means none, anything else is a failure; the exit code and the report must agree or the run is not trusted. Gitleaks assigns no severity, so every match is shown as high with "severity as reported: not supplied". Locations are `file:line` (plus the commit in history mode) and link to the containing function when there is one.

### Infrastructure checks (Checkov)

Install it yourself (`pipx install checkov`, 3.x, Apache-2.0). The workbench looks for `checkov` on `PATH`, or uses `security.iac.binary`.

```jsonc
"security": {
  "iac": {
    "exclude": ["node_modules", ".git", "dist", "build", "coverage", ".terraform", ".serverless", ".workbench"],
    "skipChecks": ["CKV_DOCKER_2"],   // inline `checkov:skip=` comments work too; both show as suppressed
    "timeoutMs": 600000
  }
}
```

- **Not applicable is not clean.** The workbench first looks for IaC files itself. With none, the run is stored as `not_applicable` with what was looked for, no counts, and Checkov is not started.
- **Only what exists is checked.** Checkov gets `--framework` with the detected frameworks only (never `secrets`, `sca_*` or `sast`). A detected framework that produced no result (Helm and Kustomize need the `helm` / `kustomize` binaries) or a file Checkov could not parse makes the run `partial`, and findings in those files are not marked as gone.
- **Offline.** No Prisma Cloud key is passed (the scanner environment is an allow-list), `--skip-download` stops guideline downloads, `BC_SKIP_MAPPING` and `CKV_SKIP_PACKAGE_UPDATE_CHECK` stop the mapping and PyPI update calls, and proxy variables are removed.
- **Results.** Each failed check keeps the check id (`CKV_AWS_24`), its name, the resource, the evaluated keys, the guideline link when present and up to 15 lines of the code block. Without a Prisma Cloud key Checkov reports no severity, so findings show `unknown` instead of a guessed level. With `--soft-fail`, a non-zero exit is a Checkov error and the run fails.

### Web scanning (Nuclei): Security tools → Web scanning, and Website comparison → Security changes

The **Website comparison** tab has two parts that are never mixed:

- **Website changes**: the existing browser comparison (screenshots, DOM assertions, behaviour) of the baseline snapshot against your current files.
- **Security changes**: [Nuclei](https://docs.projectdiscovery.io/opensource/nuclei/) template matches. A visual difference is not a vulnerability, and Nuclei does not compare screenshots.

Nuclei must already be installed by you (`brew install nuclei`, `pacman -S nuclei`, or `go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest`), and so must its templates (`nuclei -ut` once, or a clone of nuclei-templates). The workbench never installs, downloads or updates either. The panel shows the detected version (`nuclei -version`), the template directory and version (`nuclei -tv`), and setup steps when something is missing. Every flag the workbench passes is checked against the installed binary's own `-h` output.

**Workflow:** open *Website comparison → Security changes*, check the Nuclei/template status, pick a target, press *Start security scan…*, read what will be sent, tick *I am authorized to test this target*, and confirm. Progress, status and findings update live.

**Targets**
- *Baseline vs. current files*: the workbench builds and starts the baseline snapshot and a fresh snapshot of your files in throwaway copies (the same way the browser comparison does, with the same approved run commands) and scans each on a private loopback port. This is the real "baseline vs current" security comparison. It needs a baseline and approved run commands, not browser scenarios.
- *Running application URL*: an app you already run (default `http://127.0.0.1:3000`). Loopback is allowed; any other origin must be listed in `security.nuclei.authorizedTargets`. URLs with credentials, non-HTTP schemes and `0.0.0.0` are refused. The scan is compared with the previous completed scan of the same target and template set.

**Safety**
- Each scan needs an explicit confirmation (`confirm: true` is required by the API).
- Templates come only from the local template directory, limited to `security.nuclei.templates` (default `http/misconfiguration`, `http/exposures/configs`, `http/technologies`). Each template file is **inspected**, not just filtered by tag: only plain HTTP templates using the allowed methods (GET/HEAD/OPTIONS by default) pass. Templates with out-of-band interaction (interactsh), fuzzing/DAST, payload lists (brute force), attack modes, race requests, unsafe raw requests, pipelining, their own redirect following, `code`/`javascript`/`headless`/`file`/`network`/`dns`/`ssl`/workflow protocols, or a deny-listed tag (`intrusive`, `dos`, `fuzz`, `bruteforce`, `default-login`, `rce`, `oast`, `sqli`, `xss`, `ssrf`, `lfi`, …) are rejected, and the panel says why. Approved templates are copied into a per-scan folder and Nuclei is pointed only at that folder.
- Nuclei runs with `-duc` (no version check and no template install/update), `DISABLE_NUCLEI_TEMPLATES_PUBLIC_DOWNLOAD=true`, `-ni` (no interactsh), `-dr` (no redirects; or `-fhr -mr 3` with `redirects: "same-host"`), `-etags <deny list>`, `-pd=false -cup=false` (no cloud upload even if a user config enables it), rate limit 10 req/s, concurrency 5, `-bs 1`, 5 s request timeout, no retries, a 1 MB response read limit, a 10-minute run timeout, 32 MB output cap, and cancellation that kills the process group. Proxy variables are dropped for loopback targets.
- Results whose matched URL is outside the target origin are not stored as findings. Request/response dumps, curl commands and extracted values are redacted (authorization, cookies, set-cookie, API-key/token/session headers, sensitive query and body fields, JWTs, private keys, AWS keys, credential-looking extracted values) before they are stored or shown. Only the redacted JSONL is kept on disk.
- An existing `~/.config/nuclei/config.yaml` still applies to flags the workbench does not set; the panel warns when one has settings.

**Statuses:** a scan is `completed`, `incomplete` (timed out, host marked unresponsive, output limit, Nuclei loaded fewer templates than approved, or the baseline side failed), `failed` (target unreachable before the scan, Nuclei error, exit code ≠ 0, 0 templates loaded), `cancelled` or `unavailable` (Nuclei or templates missing). Failed and unavailable scans have no counts, never "0 findings".

**Comparison and lifecycle:** findings live in `graph_findings` with `source: "web"`, identified by template id + matcher/extractor name + method + endpoint (path and sorted query parameter names) within one scope (the URL origin+path, or `snapshots`). The Security changes view shows **new**, **still present**, **no longer observed** and **returned (potential regression)**. A finding becomes `not_currently_observed` only after a *completed* scan of the same scope that ran the template that reported it; failed, cancelled, incomplete and timed-out scans clear nothing, and a changed template set makes the run-to-run comparison invalid. Nuclei results are evidence that a template matched, not proof of exploitability.

**Code links:** a matched URL is linked to an endpoint and its handler only when exactly one Express route in the code graph matches the path (and the method from the request dump). Otherwise it is shown as an *unlinked web finding*, with the reason.

**Incremental scanning** (`security.nuclei.incremental`, on by default; `src/security/web/incremental.ts`, `fingerprint.ts`). A scan is rate-limited, so its cost is *templates × inputs* (measured: 7 inputs × 1,483 quick-profile templates = 11,536 requests, 230 s at 50 req/s, exactly linear in inputs). Before Nuclei runs, every input (root + graph routes) is fetched twice and a random sub-path under it twice. Signatures ignore per-request noise: timestamps, UUIDs, long tokens, nonces, CSRF values, the origin, volatile headers, and header values that differ between the two fetches. Each template is classified by what its requests can observe: `self` (`{{BaseURL}}` only), `subpath` (probes below the input; the default) or `origin` (`{{RootURL}}` only, so it runs once at `/` instead of once per input). A clean negative is cached per *(input, template)* with a context hash of what that template can see:
- *self*: the input's status, headers and normalized body, plus the code closure of its route.
- *subpath*: the input's structure, its not-found response, and the code of every route at or below it.
- *origin*: site headers and the root's not-found response.

Every context also includes the scan settings, the Nuclei version and the site infrastructure (Server, X-Powered-By, Via, CDN and technology markers, and the root's catch-all behaviour). A pair runs unless its entry is a clean negative for the same template content and the same context, and has not expired (TTL by reach: self 7 d, subpath 1 d, origin 1 d, jittered per template). Consequences:
- A changed or new route re-runs only that input.
- A code change re-runs its route, plus sub-path checks on the routes above it.
- A global header shift re-runs every input.
- An infrastructure change re-runs the whole scope.
- Pages that change structure on every request are never cached.
- A pair that has **ever** produced a finding, open or fixed, is re-run on every scan, so fixes and regressions are seen at once.
- Negatives are cached only from a *completed* Nuclei invocation, and only for pairs without a request error (`-elog`; if the build lacks it, an invocation with any request error caches nothing).

The remaining pairs are packed into as few Nuclei invocations as possible (inputs with the same templates share one; small extra overlaps are cheaper than another process). The run records what changed, why, how many checks came from the cache, and each invocation. `"fullScan": true` on `POST …/security/web/scans` ignores the cache and refreshes it. **Known limit:** content that appears at a probed path without changing anything observable (e.g. a new file dropped into a static folder, with no route, header, catch-all or code change) is caught only when the sub-path TTL expires or by a full scan.

```jsonc
"security": {
  "nuclei": {
    "binary": "/opt/homebrew/bin/nuclei",            // optional; PATH otherwise
    "templatesDir": "/home/you/nuclei-templates",     // optional absolute path; default: what `nuclei -tv` reports
    "templates": ["http/misconfiguration", "http/exposures/configs", "http/technologies"],
    "methods": ["GET", "HEAD", "OPTIONS"], "excludeTags": [], "excludeIds": [], "severities": null,
    "authorizedTargets": [],                           // e.g. ["https://staging.example.com"] — only systems you may test
    "defaultTarget": "http://127.0.0.1:3000", "redirects": "none",
    "rateLimit": 10, "concurrency": 5, "requestTimeoutSec": 5, "retries": 0, "maxHostErrors": 30,
    "maxTemplates": 1500, "maxResponseBytes": 1048576, "timeoutMs": 600000, "maxOutputBytes": 33554432,
    "incremental": { "enabled": true, "ttlHours": { "self": 168, "subpath": 24, "origin": 24 }, "maxGroups": 6, "fingerprintConcurrency": 4, "fingerprintTimeoutMs": 5000 }
  }
}
```

## Design decisions

**Analysis.** One supported path, done properly: JavaScript/TypeScript via the TypeScript compiler API, Express-style routing (`app/router.METHOD`, `app.use(prefix, router)`, middleware). Adapters produce per-file facts; a language-agnostic linker resolves them. Adding Python means writing one adapter that emits the same facts. Edges exist only when a reference resolves; client URL matches, callbacks and name-inferred routers are labelled `inferred`. Unresolved project calls are counted and shown.

**Incremental.** Facts are cached per file by content hash; a change re-parses only that file and re-links (cheap). Config or manifest changes trigger a full scan. Events are debounced, coalesced into one queue, and runs never overlap. Node IDs are symbol-based (`fn:file#qualified.name`), so line shifts don't churn identity.

**Baseline/candidate.** Baselines are explicit, content-addressed snapshots copied out of the working tree. Each run snapshots the files on disk at start, re-analyses that snapshot (so graph correlation describes the exact code that ran), builds/starts each side in a throwaway copy with a minimal env, runs scenarios, then kills only the process groups it created. If the workspace changes during a run, the result is flagged stale rather than attributed to the newer source.

**Honesty rules.** Sinks are "sensitive", never "vulnerable"; severity is deterministic and documented in `findings.ts` (no `critical`, since nothing here proves exploitability). Runtime findings are correlated to code only through requests the page actually made and assets it actually loaded; otherwise they say so. Pixel-only differences are observations. Runtime findings resolve only when a later run re-executes that scenario and it passes.

**Safety.** Loopback bind, Host/Origin checks (DNS-rebinding/CSRF), run commands require explicit approval bound to a hash of the run config, timeouts and output caps on child processes, source reads restricted to the project, artifact paths contained, secrets redacted from logs and browser evidence.

## Data model (MongoDB)

| Collection | Key fields | Indexes |
|---|---|---|
| `projects` | root, config, runHash, runApproval, baselineSnapshotId, monitoring | root (unique) |
| `file_events` | path, type, source (fs/editor/manual), contentHash, bufferState, status, analysisRunId, occurrences | (projectId, dedupeKey) unique |
| `source_snapshots` | contentHash, manifest, labels (baseline/candidate), storagePath | (projectId, contentHash) unique |
| `graph_snapshots` | graphHash, sourceHash, parserVersion, counts, graph (or file ref if > 4 MB) | (projectId, graphHash) unique |
| `analysis_runs` | trigger, status, files, sourceHash, diff, impact, summary | (projectId, startedAt) |
| `graph_findings` | source (graph/runtime/dependency/web/api/secrets/iac), category, ruleIds, location (file/line, method/url/operation, commit, resource), classification, severity, paths, evidence, correlation, status, first/lastSeen; dependency findings add ids, pkg (version, ranges, fixed versions, use evidence), scanners | (projectId, status, severityRank), (projectId, source, pkg.name, pkg.version), (projectId, ids) |
| `browser_runs` | baseline/candidate snapshot ids + hashes, sides (status/log), status, coverageNotes, staleAtFinish | (projectId, startedAt) |
| `browser_results` | side, scenario, viewport, assertions, console/network, apiRequests, assets, screenshot | (run, side, scenario, viewport) unique |
| `comparisons` | items (classification, visual diff, regions), graphChanges, filesChanged, limitations | browserRunId unique |
| `verification_records` | findingId, action (observed/reopened/verified_fixed/resolved_by_analysis/not_currently_observed/potential_regression/version_removed), evidence run | (projectId, findingId, at) |
| `security_scan_runs` (web) | category `web_dast`, mode (snapshots/url), target + scopeKey, nuclei version, template set (dir, version, hash, approved ids, rejections), settings, per-side status/exit/templates loaded/redacted report ref, counts, comparison (new/recurring/absent/returned + why not comparable), confirmation | as below |
| `security_scan_runs` (dependencies, API testing, secrets, IaC) | category (`dependency_vulns`, `api_testing`, `secrets`, `iac`), kind, mode, active + authorization, target (local URL, snapshot id), coverage (status, reason, detail), status, policy, network, per-tool records (version, status, reason, exit, report ref + sha256), per-lockfile coverage, counts (null when nothing was scanned), lockfile hashes, staleAtFinish | (projectId, category, startedAt), (projectId, status) |
| `security_observations` | immutable per-run tool observation: advisory id, aliases, package/version, published severity, range, fixed versions; rule id/name, location, original severity, confidence; for nuclei: side, template id/name/tags, matched URL, endpoint, method, matcher/extractor, redacted request/response/curl, classification | deterministic `_id` (idempotent), (projectId, findingId, observedAt), (runId, tool), (runId, side) |

| `web_endpoints` | per scan scope (URL target, or `snapshots:<side>`): one `kind: "endpoint"` doc per input (fingerprint of the input and of its not-found response, stability, code/subtree-code hashes, routes below it, header and observed technology, first/last seen, last changed, removedAt, last 20 changes with what changed) and one `kind: "site"` doc (infrastructure, site headers, cookie shapes and their hashes) | `_id` = hash(project, scope, input); (projectId, scope, kind) |
| `web_scan_cache` | one bucket per (scope, input): `entries.<templateId>` = { template sha, context hash, result `no_match`/`matched`, at, expiry, runId } | `_id` = hash(project, scope, input); (projectId, scope) — one query loads a scope; TTL index on `expiresAt` drops buckets of vanished inputs |

Screenshots, diffs and snapshot copies live under `WORKBENCH_DATA_DIR`; MongoDB stores references.

## Tests

```sh
npm test    # vitest: analyzer, graph queries, diff/classification, findings, snapshots, dependency scanners,
            # plus integration suites against real MongoDB (WORKBENCH_TEST_MONGO, skipped if unreachable)

# API testing: unit tests use real Schemathesis 4.32.4 reports; the integration suite starts the fixture app,
# and runs the real tool too when `schemathesis` is on PATH
cd packages/service && npx vitest run test/security-api.test.ts test/security-api.integration.test.ts

# Secrets and IaC: unit tests use real Gitleaks 8.24.3 and Checkov 3.3.30 reports; the real-binary tests run
# when the tools are on PATH or given explicitly
GITLEAKS_BIN=$(which gitleaks) CHECKOV_BIN=$(which checkov) npx vitest run test/security-static.test.ts test/security-static.integration.test.ts

# Optional: real nuclei against a disposable local server with two test templates (no downloads)
cd packages/service && WORKBENCH_REAL_NUCLEI=1 npx vitest run test/web-nuclei.real.test.ts   # WORKBENCH_NUCLEI_BIN=/path if not on PATH

# Optional: run every dependency scanner that is really installed against the vulnerable fixture (needs network)
cd packages/service && WORKBENCH_REAL_SCANNERS=1 npx vitest run test/security-deps.test.ts -t "real scanners"
```

## Limitations

- Languages: JS/TS only; Express-style routing only. Other frameworks' routes won't appear as endpoints (their functions and calls still will).
- Static only: dynamic dispatch, computed property calls, DI containers and barrel re-exports (`export * from`) are not resolved. No data-flow/taint tracking; sink input origin is a hint.
- Client↔endpoint links are string-literal URL matches.
- `linkNodeModules` shares the workspace's `node_modules` between baseline and candidate; dependency changes are flagged, not isolated.
- Scenarios cover only what you configure; untested pages can still regress.
- The OSV.dev web API adapter needs only `security.allowNetwork: true` and outbound HTTPS to `api.osv.dev`; readiness probes it and shows `service unreachable` if it does not answer. Trivy has no hosted API, so it stays a local-binary option. The web adapter is tested against a fake `fetch` shaped like the documented responses, not yet against the live API.
- Dependency scanning covers the root npm lockfile only. Other ecosystems and nested workspaces are detected and reported as not scanned. OSV-Scanner and Trivy adapters are tested against synthetic reports until they are run against real output.
- Nuclei: template vetting reads the YAML line by line (no YAML parser); anything it cannot classify is rejected, so some harmless templates may be excluded. URL-mode graph links use the current working-tree graph, which may differ from the code the running app was started from. The nuclei adapter's parsing is tested against synthetic output written from the nuclei source's `ResultEvent` struct until it has been run against a real binary (see `test/fixtures/web/README.md`).
- Not integrated yet: OWASP ZAP, Syft/Grype (SBOM and SBOM-based vulnerability scanning), Semgrep and CodeQL. Their ids exist only as dashboard labels.
- Gitleaks and Checkov have been verified on Linux with Gitleaks 8.24.3 and Checkov 3.3.30; other versions are accepted (Gitleaks 8.19+, Checkov 3.x) but have not been run.
- The AI agent (`packages/orchestrator`) probes `http://127.0.0.1:3000` directly (`auth_probe`, `sqli_probe`): it does not use the managed-target authorisation flow of API testing, so only run it against your own local app. It sends the model only an endpoint's method and path, to a local Ollama.
- The extension is a thin client and has been compiled but should be smoke-tested in your VS Code.
