# Web-scan (nuclei) fixtures

All files here are **hand-written and test-only**; none come from the public nuclei-templates repository.

| Path | Purpose |
|---|---|
| `templates/http/misconfiguration/workbench-canary-header.yaml` | Safe GET template. Matches the `X-Workbench-Canary: exposed` header the disposable test server sends on `/canary`. Used by the real-nuclei test and the vetting tests. |
| `templates/http/exposures/workbench-debug-page.yaml` | Safe GET template. Matches `/debug` only when the test server runs in "vulnerable" mode, so a re-scan can show the finding as absent. |
| `unsafe/*.yaml` | Templates the vetting **must reject**: out-of-band (interactsh), POST, raw PUT, payload brute force, `intrusive` tag (list form), `code` protocol, fuzzing. They are never executed. |
| `nuclei-output.synthetic.jsonl` | **Synthetic** nuclei `-jsonl` output written from the `output.ResultEvent` struct in the nuclei source (pkg/output/output.go). Contains secrets that must be redacted, a duplicate, an out-of-scope result and a malformed line. The real run (below) confirmed the field names used by the parser. |
| `nuclei-output.real.jsonl` | **Real**: summary (template id, matched URL, severity, extracted values) of what nuclei v3.11.1 (Homebrew, macOS arm64) reported against the disposable test server, written by `web-nuclei.real.test.ts` on 2026-10-24. Regenerated on every real run. |
