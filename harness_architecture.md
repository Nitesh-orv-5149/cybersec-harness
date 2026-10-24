# Harness architecture: current vs. vision

## Current (what's built and running)

```
sample-app (Express, :3000)
  routes/orders.js, routes/users.js, routes/tools.js
  src/services, src/lib, src/middleware
  public/ (static frontend)
        │
        │ file changes on disk
        ▼
chokidar file watch ──► local service (Node/TS, 127.0.0.1:4317)
editor events (VS Code ext) ─┘      │
                                     ├─ analyzer: TS compiler API → per-file facts → linker → graph
                                     ├─ debounce/coalesce queue → incremental re-parse → graph diff → impact
                                     ├─ snapshots (content-addressed, baseline vs candidate)
                                     ├─ runner (approved build/start commands, process groups)
                                     ├─ Playwright scenarios → pixelmatch diff → classification
                                     ├─ findings: deterministic rules + runtime↔graph correlation
                                     └─ MongoDB (10 collections: events, snapshots, graphs,
                                        analysis runs, findings, browser runs/results,
                                        comparisons, verification records)
                                     │
                                     ▼
                              dashboard (React + Cytoscape, :5173 dev / served by :4317)
                              live over WebSocket — graph view, impact, reachability,
                              browser-diff comparisons, history
```

Confirmed live: editing `sample-app/src/routes/orders.js` (e.g. adding a new endpoint) is
picked up by chokidar within ~1s, re-parsed, and reflected in `graphVersion` /
`nodeCount` / `edgeCount` without restarting anything. No Git integration — the trigger is
a local file change, not a merge or commit.

What this does **not** do yet: no autonomous decision-making, no deliberate vulnerability
hunting, no LLM/agent loop. "Findings" are static deterministic rules (sensitive sinks,
auth gaps the analyzer can see structurally) plus visual/assertion regressions from
browser scenarios — not a security scan.

## Vision (the actual product goal)

```
sample-app (Express, :3000) ── intentionally vulnerable fixture
        │
        │ file changes on disk (API modified)
        ▼
chokidar file watch ──► local service (:4317)  [unchanged from current]
                            │
                            ├─ analyzer/graph/snapshots/runner/browser  [unchanged]
                            │
                            ▼
                    NEW: agent orchestrator
                            │
              ┌─────────────┼──────────────────┐
              ▼              ▼                  ▼
        cybersec tool A  cybersec tool B   cybersec tool C
        (e.g. static     (e.g. dependency   (e.g. dynamic probe
         taint/SAST       / CVE check)       against running
         pass)                               sample-app:3000)
              │              │                  │
              └──────────────┴──────────────────┘
                            │
                            ▼
                 correlate findings + reasoning
                            │
                            ▼
              MongoDB — agent memory
              (past findings, what's already been tried,
               fix/regression status across runs, so the
               agent doesn't re-report or re-probe blindly)
                            │
                            ▼
              structured findings output
              (schema TBD — likely extends today's
               graph_findings shape: severity, evidence,
               correlation, status)
                            │
                            ▼
                    dashboard: findings panel
```

The trigger stays the same (local API/file change via chokidar — confirmed working, no
Git merge needed). What's missing is everything from "agent orchestrator" down: an agent
that, on each graph-affecting change, decides which cybersec tools to run against the
affected endpoints, executes them, and writes correlated, deduplicated findings to Mongo
as durable agent memory instead of ephemeral per-run output.

## Gap summary

| Piece | Current | Vision |
|---|---|---|
| Trigger | chokidar file watch (confirmed working) | same — no change needed |
| Decision-making | none (deterministic rules only) | agent orchestrator picks/runs tools per change |
| Tools | TS analyzer + Playwright visual diff | + SAST/dependency/dynamic-probe tools |
| MongoDB role | run history (events, snapshots, findings) | + agent memory (cross-run reasoning, dedup, fix tracking) |
| Output | graph + visual-diff findings | structured vuln findings, schema TBD |
