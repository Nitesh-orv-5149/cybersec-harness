# Merge report: security workbench (ZIP A + ZIP B)

Date: 2026-10-24. Inputs:
- **ZIP A** `cybersec-harness_2_2.zip`: git repo on branch `llm-orchestrator` (last commit `bc6680b`) **plus ~30 uncommitted files** (the whole Nuclei integration).
- **ZIP B** `code-impact-workbench-3.zip`: branch `feat/security-scanning` (commits `a315fe3`, `1e6feec`) plus 13 uncommitted fixes; no `.git`.

Both descend from commit `e5fc7f0` (dependency scanning). Neither archive was modified; all work happened in a separate scratch repository.

## 1. Base and method

**A is the base**, merged with B by a real three-way git merge (merge base `e5fc7f0`), for these reasons:
- A carries the git history, the AI agent (orchestrator + dashboard tab), the Nuclei module (the largest and most self-contained piece), and project-scoped ids for shared databases.
- B's work is additive and lives mostly in new directories (`security/scan`, `security/api`, `security/secrets`, `security/iac`).
- Both archives have identical dependency sets (no lockfile package differences), so no dependency merge was needed.

Git merged most files automatically. 8 files conflicted and were consolidated by hand: `README.md`, `App.tsx`, `api.ts`, `IssuesView.tsx`, `config.ts`, `project.ts`, `exec.ts` and `security/types.ts`.

## 2. Feature matrix (verified by reading the code and running the tests)

| Feature | A | B | Merged |
|---|---|---|---|
| Code graph (JS/TS, Express) | Fully | Fully, plus handler factories (`app.get(p, wrap(factory()))`) | Fully, with B's analyzer (parser version `js-ts-express@2`) |
| Website comparison (visual/DOM/behaviour) | Fully | Fully | Fully; unchanged behaviour, dashboard test renders it |
| Security comparison (Nuclei baseline vs current) | Fully (mocked process; A records one real Nuclei 3.11.1 run on macOS) | Missing | Fully; real run not repeated here |
| Nuclei (URL mode, incremental cache, template vetting, redaction) | Fully, but its process was never run in A's test suite | Missing (label only) | Fully; real execution unverified here |
| Dependency scanning (npm audit, OSV.dev API, OSV-Scanner, Trivy) | Fully + `tools` selection for the agent | Fully | Fully (both changes kept) |
| API testing (Schemathesis, managed local target, authorisation) | Partially (config groundwork only, no adapter) | Fully | Fully; real Schemathesis 4.32.4 run passes |
| Secrets (Gitleaks, redaction, workspace/history) | Missing | Fully | Fully; real Gitleaks 8.24.3 run passes |
| IaC (Checkov, offline, not-applicable handling) | Missing | Fully | Fully; real Checkov 3.3.30 run passes |
| Generic scan framework (ScanKind/ScanService, lifecycle) | Missing | Fully | Fully |
| AI agent (Python orchestrator + agent events API + tab) | Fully (needs local Ollama; falls back to all tools) | Missing | Fully, but not executed in this merge (Python, local model) |
| Project-scoped ids for a shared database | Fully (+ migration of old finding ids) | Missing | Fully; B's managed-target snapshots now use the scoped id too |
| Config tolerance (bad browser step doesn't reset config) | Missing | Fully | Fully |
| Clear message for a broken pipx tool (`ENOENT` from a missing `#!` interpreter) | Missing | Fully | Fully |
| Dashboard fix for install paths containing spaces | Missing | Fully | Fully |
| Juice Shop example config | Missing | Fully | Fully |
| ZAP, Syft, Grype, Semgrep, CodeQL | Missing | Missing (labels only) | Missing; their ids are typed as `PlannedToolId`, a label only |

## 3. Consolidations (overlaps resolved, not duplicated)

- **Exec environment option.** A had `extraEnv` and B had `env` for the same thing. The merge keeps one, `extraEnv`, and renames B's two callers (Checkov kind and test). Also kept: B's `discardStdout` (it now also feeds A's `onStdout` stream), and A's streaming hooks, `stderrTailBytes` and pre-start abort.
- **Tool ids.** `AnyToolId` is now `ToolId` (deps) | `ApiToolId` (schemathesis) | `WebToolId` (nuclei) | `StaticToolId` (gitleaks, checkov) | `PlannedToolId` (zap, semgrep, syft, grype: labels only).
- **Config.** `security.nuclei` (A) and `security.secrets` / `security.iac` (B) live side by side. A file with a bad browser step still loads all of them.
- **Project session.** `deps` (both), `web` (A's two-snapshot `WebScanService`) and `scans` (B's per-category `ScanService` map) coexist, and `status().security` exposes `dependencies`, `web` and `scans`. Nuclei stays outside B's ScanKind framework on purpose: it scans two snapshots in one run and has an incremental cache, which the single-target ScanKind contract does not model. No kind in B's registry uses `source: 'web'`, so the two lifecycles never touch each other's findings.
- **Dashboard navigation.**
  - Tabs are Dependency scan, Security tools, AI agent and History. A's "Dependency & web scan" label is gone.
  - Nuclei is reachable from **Security tools → Web scanning**, a new entry using A's `WebSecurityPanel`, and from **Website comparison → Security changes** (A). It was moved out of the Dependency scan tab, so it no longer appears in three places.
- **Finding detail.** Nuclei findings use A's evidence view (`WebDetail`). API, secrets and IaC findings use B's `ScanDetail`. Source labels come from one `SOURCE_NAME` table.
- **README.** Rebuilt from both versions, plus a macOS setup section.

## 4. Database and configuration

- **Collections.** The merged set is the union. A adds `agent_events`, `web_endpoints` and `web_scan_cache` (with TTL index). B adds no collections.
- **`security_scan_runs.category`.** Values are `dependency_vulns`, `web_dast` (Nuclei), `api_testing`, `secrets` and `iac`. There are no clashes.
- **`graph_findings.source`.** Values are `graph`, `runtime`, `dependency`, `web` (Nuclei), `api`, `secrets` and `iac`.
- **Migrations.**
  - A's `migrateFindingIds` copies old unscoped graph/runtime finding ids to project-scoped ids and repoints their verification records. It then removes the old documents; no information is lost.
  - B's parser-version bump only invalidates the per-file analysis cache.
  - No existing data is deleted otherwise.
- **New files.**
  - `.env.example`. Nothing reads `.env` automatically; use `node --env-file=.env …`.
  - `examples/juice-shop.workbench.config.json`.
  - `.gitignore` now also ignores `.DS_Store` and `__MACOSX/`.

## 5. Tests actually run (Linux, Node 22, MongoDB 8 running, 2026-10-24)

| Check | Result |
|---|---|
| `npm run typecheck` (service, dashboard, extension) | pass |
| `npm run build` (dashboard, service, extension) | pass |
| `npm test`, service | **234 passed, 4 skipped**, 0 failed (15 files) |
| `npm test`, dashboard | **11 passed** |
| Lint | not configured in either project |
| Browser check of the built dashboard on a sample-app copy | every tab rendered, no console errors; a Checkov run from the UI stored 14 findings |

Skipped (4):
- the dependency "real scanners" test (opt-in, needs network)
- the three real-Nuclei tests: `nuclei` isn't installed here, and installing it wasn't approved for this task

Baselines before merging, run the same way:
- **A, unmodified:** 176 passed, 2 failed, 4 skipped. The failures:
  1. A dependency test reached the live OSV API. B's offline-`fetch` fix resolves it.
  2. A session test expected 4 affected endpoints, but A's own two new sample routes make it 6. The test now lists all 6 by name, after confirming each is a real caller of `formatCurrency`.

  With MongoDB down, A's run shows 175 passed and 7 skipped, which hides these two failures.
- **B, unmodified:** 135 passed, 1 skipped.

## 6. Real executions vs fixtures

- **Real, in this merge:**
  - Schemathesis 4.32.4: a run against a disposable local app, finding the SQL-quote 500.
  - Gitleaks 8.24.3: workspace scan of fake credentials built at runtime; the test checks nothing unredacted reaches MongoDB or disk.
  - Checkov 3.3.30: offline run on the IaC fixture, in tests and from the dashboard.
  - npm (readiness only).
- **Recorded real output, replayed:** the Schemathesis, Gitleaks and Checkov report fixtures, and A's `nuclei-output.real.jsonl` (A records it as Nuclei 3.11.1 on macOS arm64).
- **Mocked or synthetic only:**
  - Nuclei process behaviour: failures, timeouts, cancellation and incremental planning.
  - OSV-Scanner and Trivy (synthetic reports).
  - OSV.dev API (fake `fetch`).
  - The Python orchestrator, which was not executed.

## 7. Remaining issues and unverified functionality

- Nuclei real execution was not re-run here. On a Mac: `brew install nuclei`, then `WORKBENCH_REAL_NUCLEI=1 npx vitest run test/web-nuclei.real.test.ts` in `packages/service`. This uses local test templates only, with no downloads.
- The AI agent's `auth_probe` / `sqli_probe` send requests straight to `127.0.0.1:3000`. They bypass the API-testing authorisation flow, so only point it at your own app. Not executed in this merge.
- OSV-Scanner and Trivy adapters are still verified only against synthetic reports. The networked "real scanners" test is opt-in.
- Juice Shop was analysed statically only. Running its install scripts was blocked in this environment, so the managed-target flow is untested on it.
- ZAP, Syft, Grype, Semgrep and CodeQL are not integrated.
- A Gitleaks scan of the packaged tree flags 9 values. All are in A's Nuclei redaction tests (`web-nuclei.test.ts`, `fixtures/web/nuclei-output.synthetic.jsonl`) and are synthetic placeholders (alphabetical AWS-style and test-pattern Stripe-style strings). They are kept because the tests prove they get redacted. GitHub push protection may still ask you to confirm them when this tree is pushed.

## 8. Extract, configure, start

```sh
unzip security-workbench-merged.zip && cd security-workbench-merged
brew services start mongodb-community        # or any MongoDB 6+; see README "macOS setup"
npm install && npm run build
node packages/service/dist/cli.js --project ./sample-app     # http://127.0.0.1:4317
npm test                                      # service + dashboard tests (MongoDB tests skip if it is down)
```
Scanner installation, safe-scan rules and troubleshooting: README, section "macOS setup".
