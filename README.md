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
| `graph_findings` | source (graph/runtime/dependency), classification, severity, paths, evidence, correlation, status, first/lastSeen; dependency findings add ids, pkg (version, ranges, fixed versions, use evidence), scanners | (projectId, status, severityRank), (projectId, source, pkg.name, pkg.version), (projectId, ids) |
| `browser_runs` | baseline/candidate snapshot ids + hashes, sides (status/log), status, coverageNotes, staleAtFinish | (projectId, startedAt) |
| `browser_results` | side, scenario, viewport, assertions, console/network, apiRequests, assets, screenshot | (run, side, scenario, viewport) unique |
| `comparisons` | items (classification, visual diff, regions), graphChanges, filesChanged, limitations | browserRunId unique |
| `verification_records` | findingId, action (observed/reopened/verified_fixed/resolved_by_analysis/not_currently_observed/potential_regression/version_removed), evidence run | (projectId, findingId, at) |
| `security_scan_runs` | category, status, policy, network, per-tool records (version, status, reason, exit, report ref + sha256), per-lockfile coverage, counts (null when nothing was scanned), lockfile hashes, staleAtFinish | (projectId, category, startedAt), (projectId, status) |
| `security_observations` | immutable per-run tool observation: advisory id, aliases, package/version, published severity, range, fixed versions | deterministic `_id` (idempotent), (projectId, findingId, observedAt), (runId, tool) |

Screenshots, diffs and snapshot copies live under `WORKBENCH_DATA_DIR`; MongoDB stores references.

## Tests

```sh
npm test    # vitest: analyzer, graph queries, diff/classification, findings, snapshots, dependency scanners,
            # plus integration suites against real MongoDB (WORKBENCH_TEST_MONGO, skipped if unreachable)

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
- The extension is a thin client and has been compiled but should be smoke-tested in your VS Code.
