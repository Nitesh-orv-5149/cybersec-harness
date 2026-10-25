# API testing fixtures

- `items-app/`: small Express app used as a disposable local target. `GET /api/items/search` builds a SQL
  string from `q`, and the fake database raises a syntax error on an unbalanced quote, so the endpoint
  answers 500 for `q='`. The app is a test fixture only.
- `schemathesis-4.32.4.run.json`, `schemathesis-4.32.4.events.ndjson`: **real** Schemathesis 4.32.4 output
  from a workbench API-testing run against `items-app` (graph-derived schema, seed 7). Temporary paths were
  replaced with `/tmp/workbench-data/redacted`; nothing else was edited.
- `graph-derived.openapi.json`: the schema the workbench generated from the code graph for that run.
