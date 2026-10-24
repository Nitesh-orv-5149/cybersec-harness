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

### VS Code extension

```sh
cd packages/extension && npm run build
# then either open this folder in VS Code and press F5, or: npx @vscode/vsce package && code --install-extension *.vsix
```

Commands: *Start monitoring this workspace*, *Open dashboard*, *Mark current files as baseline*, *Compare current files with baseline*, *Re-analyse*, *Full rescan*. The status bar shows analysis/website state. Unsaved buffers are sent (debounced) for analysis only; the graph marks them with a dashed outline and website runs never include them. "Open in editor" in the dashboard jumps to the source location.

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
| `graph_findings` | source (graph/runtime), classification, severity, paths, evidence, correlation, status, first/lastSeen | (projectId, status, severityRank) |
| `browser_runs` | baseline/candidate snapshot ids + hashes, sides (status/log), status, coverageNotes, staleAtFinish | (projectId, startedAt) |
| `browser_results` | side, scenario, viewport, assertions, console/network, apiRequests, assets, screenshot | (run, side, scenario, viewport) unique |
| `comparisons` | items (classification, visual diff, regions), graphChanges, filesChanged, limitations | browserRunId unique |
| `verification_records` | findingId, action (observed/reopened/verified_fixed/resolved_by_analysis), evidence run | (projectId, findingId, at) |

Screenshots, diffs and snapshot copies live under `WORKBENCH_DATA_DIR`; MongoDB stores references.

## Tests

```sh
npm test    # vitest: analyzer, graph queries, diff/classification, findings, snapshots,
            # plus an integration suite against real MongoDB (WORKBENCH_TEST_MONGO, skipped if unreachable)
```

## Limitations

- Languages: JS/TS only; Express-style routing only. Other frameworks' routes won't appear as endpoints (their functions and calls still will).
- Static only: dynamic dispatch, computed property calls, DI containers and barrel re-exports (`export * from`) are not resolved. No data-flow/taint tracking; sink input origin is a hint.
- Client↔endpoint links are string-literal URL matches.
- `linkNodeModules` shares the workspace's `node_modules` between baseline and candidate; dependency changes are flagged, not isolated.
- Scenarios cover only what you configure; untested pages can still regress.
- The extension is a thin client and has been compiled but should be smoke-tested in your VS Code.
