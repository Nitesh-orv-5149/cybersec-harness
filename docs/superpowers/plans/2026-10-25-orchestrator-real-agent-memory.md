# Orchestrator Real Agent-Memory Integration Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace the Python orchestrator's dummy `memory.json` store with the real Mongo-backed agent-memory API (`packages/service/src/agentMemory.ts`), and fix the two reliability gaps the live LLM test surfaced: memory-driven skipping must be deterministic, not left to the LLM's free-text reading, and each memory must be addressable per-tool, not lumped per-endpoint.

**Architecture:** A new thin HTTP client module (`packages/orchestrator/agent_memory.py`), mirroring the existing style of `harness.py`, replaces `memory.py`. Every stored memory's content is prefixed with a machine-readable verdict tag (`[clean]` / `[finding]`) and keyed per-tool (`subject.key = "<tool>|<method> <path>"`), so "has this tool already cleared this exact endpoint" is a deterministic lookup in code — never something the LLM has to infer from prose. Tools already confirmed clean are removed from the candidate list *before* the LLM is asked anything; only tools with no clean verdict (first run, or a past finding worth re-checking) reach `llm.choose_tools`, and any finding-type memories for those are passed in as structured context. The existing `harness.log_event` activity feed (dashboard-facing, collection `agent_activity`) is untouched — this plan adds the separate run/episodic-event/memory trace (`agent_runs`/`agent_events`/`agent_memories`) alongside it, not instead of it.

**Tech Stack:** Python (`requests`), the harness's existing `/api/projects/:id/agent/*` REST API. No new dependencies. No pytest: this package has no test infra today (its existing modules are verified by running them against the live stack, e.g. `agent_demo.mjs`'s role for the TS side) — each task here is verified the same way, against the real running harness + Ollama, not mocked.

**Spec:** this conversation (2026-10-25) — no separate spec doc; requirements captured directly below from the user's four-part request and from the live-LLM test's two findings (misattributed memory skip, per-endpoint-not-per-tool memory granularity).

## Global Constraints

- No new Python dependencies beyond `requests` (already in `requirements.txt`).
- Memory subject types must be one of the server's fixed enum: `finding | endpoint | package | tool | project` (`packages/service/src/store/agentMemory.ts` `SUBJECT_TYPES`) — code here uses `endpoint` for probe-tool memories and `package` for dependency-scanner memories, never a made-up type.
- Stored memory `content` must start with `[clean] ` or `[finding] ` — this is the deterministic signal; nothing downstream may rely on the LLM re-deriving verdict from free text.
- The existing `harness.log_event` dashboard activity calls in `main.py` stay exactly as they are; this work adds to `main.py`, it does not remove the activity feed.
- `packages/orchestrator/memory.py` and `memory.json` are deleted outright once nothing references them — no backwards-compat shim, no re-export.

## Review Focus

- **Ollama unreachable mid-run:** `llm.choose_tools` already has a fallback path (run everything); the new memory-aware prompt must not break that fallback when `memories` is empty or when the request fails before memory is even read.
- **A memory exists but is `unverified`/`superseded`/`retired`:** `recall()` only returns `active` (and optionally `unverified`) memories server-side — the client's `already_clean` check must not treat a stale or retired "clean" memory as still valid if a newer memory superseded it.
- **First run ever for an endpoint (no memory at all):** `recall` returns `[]`; the deterministic pre-filter must pass every candidate tool through unchanged, identical to today's dummy-memory-less behavior.
- **Same tool, same endpoint, re-run after a code change:** a `[clean]` memory from before a file change should not silently suppress re-probing forever — covered by giving stored "clean" memories a bounded `ttlHours` so they expire rather than acting as a permanent skip.
- **Dependency-scanner dedup path** (`already_found(tool, advisoryId)` in the old dummy memory) must be migrated too, not left on the dummy store, or half the orchestrator will still depend on `memory.json` after this plan.

---

## Task 1: Real agent-memory HTTP client

**Files:**
- Create: `packages/orchestrator/agent_memory.py`
- Delete: `packages/orchestrator/memory.py`, `packages/orchestrator/memory.json`

**Interfaces:**
- Produces (used by Tasks 2–4):
  - `start_run(project_id: str, goal: str, subject: dict | None = None) -> dict` — POSTs `/agent/runs`, returns the run doc (has `_id`).
  - `log_step(project_id: str, run_id: str, type: str, status: str = "ok", **kw) -> dict` — POSTs `/agent/runs/{run_id}/events`, returns the event doc (or `{}` on a 4xx rejection, printed not raised).
  - `finish_run(project_id: str, run_id: str, status: str, **kw) -> dict` — POSTs `/agent/runs/{run_id}/finish`.
  - `recall(project_id: str, subject_type: str, subject_key: str) -> list[dict]` — GETs `/agent/memories?subject=...`, returns `active`-only memories for that exact subject key (filters out ones whose `subject.type` doesn't match, since the server only filters by `subject.key`).
  - `remember(project_id: str, run_id: str, subject_type: str, subject_key: str, verdict: str, note: str, confidence: str = "medium", evidence: list[dict] | None = None, ttl_hours: int | None = None) -> dict` — POSTs `/agent/memories` with `content = f"[{verdict}] {note}"`; `verdict` must be `"clean"` or `"finding"`.
  - `already_clean(project_id: str, subject_type: str, subject_key: str) -> bool` — `True` iff `recall(...)` returns at least one memory whose `content` starts with `"[clean] "` (most recent wins; `recall` is already sorted by `updatedAt desc`).

- [ ] **Step 1: Write `agent_memory.py`**

Base URL and session reuse `harness.HARNESS_HTTP` (import `harness`, don't redefine the constant). Each function is a direct `requests` call matching the signatures above; `log_step` and `remember` catch `requests.RequestException` and print a warning rather than raising (same best-effort pattern as `harness.log_event`), since a memory-logging failure must never stop an investigation. `recall` and `start_run`/`finish_run` are allowed to raise — a broken run start is a real failure the caller should see.

- [ ] **Step 2: Delete `memory.py` and `memory.json`**

```bash
git rm packages/orchestrator/memory.py packages/orchestrator/memory.json
```

- [ ] **Step 3: Verify against the live stack**

With the harness service running (`node packages/service/dist/cli.js --project ./sample-app`) and Mongo reachable:

```bash
packages/orchestrator/.venv/bin/python -c "
import agent_memory as am, harness
pid = harness.project_id()
run = am.start_run(pid, 'plan task 1 smoke check')
am.log_step(pid, run['_id'], 'plan', outputSummary='checking client')
assert am.recall(pid, 'endpoint', 'smoke-test-key') == []
mem = am.remember(pid, run['_id'], 'endpoint', 'smoke-test-key', 'clean', 'nothing found', ttl_hours=1)
assert mem['content'] == '[clean] nothing found'
assert am.already_clean(pid, 'endpoint', 'smoke-test-key') is True
am.finish_run(pid, run['_id'], 'completed', summary='ok')
print('PASS')
"
```

Expected: prints `PASS` with no exceptions.

- [ ] **Step 4: Commit**

```bash
git add packages/orchestrator/agent_memory.py
git commit -m "feat(orchestrator): real Mongo-backed agent-memory client, replacing the dummy JSON store"
```

## Task 2: Memory-aware, deterministic-skip tool selection

**Files:**
- Modify: `packages/orchestrator/llm.py`

**Interfaces:**
- Consumes: nothing new (pure function change).
- Produces (used by Task 3): `choose_tools(endpoint: dict, available: list[str], memories: list[dict] | None = None) -> tuple[list[str], str]` — same return shape as today. `memories` is a list of memory docs (each has `content` starting `[finding] ...`) for tools that are *not* deterministically clean; the function must never receive `[clean]` memories (that filtering happens in `main.py`, Task 3) — this function only has to render whatever list it's given.

- [ ] **Step 1: Change `choose_tools`'s signature and prompt**

Add `memories: list[dict] | None = None`. When non-empty, append a block before the final instruction:

```
Memory from earlier runs on this endpoint (each line names the exact tool it's about):
- auth_probe: finding — <memory content with the "[finding] " prefix stripped>
These are past findings, not guarantees they still reproduce — re-run them if you think they're
still relevant; this is just context, not an instruction to skip.
```

Build each line as `f"- {tool_name_parsed_from_content_or_passed_separately}: finding — {text}"`. Since `recall()`'s memory docs don't carry the tool name directly (it's embedded in `subject.key` as `"<tool>|<method> <path>"`), parse the tool name from `m['subject']['key'].split('|')[0]` when rendering each line — don't ask the LLM to infer which tool a memory is about from prose (that's the exact failure the live test found).

- [ ] **Step 2: Verify against the live stack**

```bash
packages/orchestrator/.venv/bin/python -c "
from llm import choose_tools
chosen, reason = choose_tools({'method': 'GET', 'path': '/api/orders/:id/receipt'}, ['auth_probe', 'sqli_probe'],
    memories=[{'subject': {'key': 'auth_probe|GET /api/orders/:id/receipt'}, 'content': '[finding] returned 200 with no auth header'}])
print(chosen, reason)
assert reason.startswith('llm:') or reason.startswith('fallback:')
print('PASS')
"
```

Expected: `PASS`, and — with Ollama reachable — a real `llm: <model>` reason (confirms the memory block didn't break JSON parsing).

- [ ] **Step 3: Commit**

```bash
git add packages/orchestrator/llm.py
git commit -m "feat(orchestrator): pass per-tool memory context into the LLM prompt, with the tool name parsed from subject.key, not inferred"
```

## Task 3: Wire endpoint-probe investigation through real agent memory

**Files:**
- Modify: `packages/orchestrator/main.py` (`investigate()` and `available_tools()`)

**Interfaces:**
- Consumes: `agent_memory.{start_run, log_step, finish_run, recall, remember, already_clean}` (Task 1), `llm.choose_tools(endpoint, available, memories)` (Task 2).
- Produces: `investigate()` keeps its existing signature `(project_id, endpoint, available, run_deps)`; callers in `watch()` are unchanged.

- [ ] **Step 1: In `investigate()`, before calling `llm.choose_tools`, split `available` into clean-skipped vs. candidate**

For the endpoint-probe tools only (`ENDPOINT_TOOLS & set(available)`), for each tool build `key = f"{tool}|{ep}"` (reuse the existing `ep = f"{endpoint['method']} {endpoint['path']}"` local) and drop it from the candidate list if `agent_memory.already_clean(project_id, 'endpoint', key)` is `True`; log one `log_event(project_id, "tool_result", f"{name}: skipped (memory: already clean)", ...)` per skipped tool so it's visible in the dashboard activity feed exactly like the existing `memory.already_found` skip message was. Dependency tools (`DEPENDENCY_TOOLS`) pass through unchanged here — their dedup is Task 4.

- [ ] **Step 2: Start a run, recall finding-type memories for the surviving candidates, call the LLM**

```python
run = agent_memory.start_run(project_id, f"Investigate {ep}", subject={"endpointPath": endpoint["path"]})
memories = []
for name in candidate_probe_tools:
    memories += [m for m in agent_memory.recall(project_id, "endpoint", f"{name}|{ep}") if m["content"].startswith("[finding]")]
agent_memory.log_step(project_id, run["_id"], "memory_read", outputSummary=f"{len(memories)} finding memory(ies) recalled")
chosen, reason = llm.choose_tools(endpoint, available, memories)  # `available` here = after Step 1's skip, deps untouched
agent_memory.log_step(project_id, run["_id"], "decision", outputSummary=f"chose {chosen} ({reason})")
```

- [ ] **Step 3: After each probe tool runs, record the outcome as a memory (both clean and finding), not only findings**

Replace the existing `memory.already_found(name, endpoint["path"])` / `memory.insert_one(result)` calls in the probe loop: after `result = tools.TOOLS[name](endpoint)`,

```python
key = f"{name}|{ep}"
if result is None:
    agent_memory.remember(project_id, run["_id"], "endpoint", key, "clean", "ran, nothing found", ttl_hours=24*7)
    agent_memory.log_step(project_id, run["_id"], "tool_call", tool=name, status="ok", outputSummary="clean")
else:
    agent_memory.remember(project_id, run["_id"], "endpoint", key, "finding", result["summary"],
                           confidence="medium", evidence=[{"kind": "event", "id": run["_id"]}])
    agent_memory.log_step(project_id, run["_id"], "tool_call", tool=name, status="ok", outputSummary=result["summary"])
```

Keep every existing `harness.log_event(...)` call exactly where it is (dashboard feed is unaffected) — these `agent_memory.log_step` calls are additions alongside them, not replacements.

- [ ] **Step 4: Finish the run**

At the end of the probe-tool loop (before the dependency-scanner section begins), call `agent_memory.finish_run(project_id, run["_id"], "completed", summary=f"ran {chosen}")`. If the loop raises, that's an existing uncaught-exception path in `investigate()` today — leave it as is (out of scope for this plan).

- [ ] **Step 5: Verify against the live stack — two consecutive investigations of the same endpoint**

With the harness + sample-app + Ollama running:

```bash
packages/orchestrator/.venv/bin/python -c "
import harness, main
pid = harness.project_id()
ep = {'method': 'GET', 'path': '/api/orders/:id/receipt'}
avail = main.available_tools(pid)
main.investigate(pid, ep, avail, run_deps=False)
main.investigate(pid, ep, avail, run_deps=False)
print('ran twice, check Mongo agent_runs/agent_events/agent_memories for two runs and a deterministic skip on the second')
"
```

Expected: inspecting Mongo afterward (`agent_memories` filtered by `subject.key` containing the endpoint path) shows one `[clean]` or `[finding]` memory per tool, and the second `investigate()` call's printed/logged output shows at least one tool skipped by the deterministic `already_clean` check (not by the LLM) — confirms Review Focus item "same tool, same endpoint, re-run" is handled in code, not by hoping the model agrees twice in a row.

- [ ] **Step 6: Commit**

```bash
git add packages/orchestrator/main.py
git commit -m "feat(orchestrator): wire endpoint-probe investigation through real agent memory, with deterministic clean-tool skipping"
```

## Task 4: Migrate dependency-scanner dedup off the dummy store

**Files:**
- Modify: `packages/orchestrator/main.py` (the `dep_tools` block in `investigate()`)

**Interfaces:**
- Consumes: `agent_memory.{already_clean, remember}` (Task 1), same `run` object started in Task 3 Step 2 (dependency-scanner block runs inside the same `investigate()` call, after the probe-tool loop, so it reuses `run["_id"]`).

- [ ] **Step 1: Replace the dependency-finding dedup check**

The current code:
```python
if memory.already_found(f["tool"], f["evidence"].get("advisoryId")):
    continue
saved = memory.insert_one({**f, "endpoint": f["evidence"].get("advisoryId")})
```
becomes, per finding `f` returned by `tools.run_dependency_scanners`:
```python
key = f"{f['tool']}|{f['evidence'].get('advisoryId')}"
if agent_memory.already_clean(project_id, "package", key):  # a prior run already reported this, see note below
    continue
saved = {**f, "endpoint": f["evidence"].get("advisoryId")}
agent_memory.remember(project_id, run["_id"], "package", key, "finding", saved["summary"],
                       evidence=[{"kind": "scan_run", "id": f["evidence"].get("runId") or ""}])
```
Note the semantic shift: the old dedup suppressed a finding forever once seen once. Here, `already_clean` checks for a `[clean]` verdict, which dependency findings never write (there is no "ran trivy, found nothing" per-advisory memory — clean dependency scans are already reported via the existing `harness.log_event(..., "clean", ...)` path a few lines below, unchanged). So this dedup is effectively now a no-op gate that always passes through — **intentionally**: write the finding memory for traceability, but do not suppress a real, currently-open vulnerability from being reported again just because a past run also saw it. Re-reporting an open CVE every change batch is correct behavior; silently hiding it was the dummy store's actual bug, not a feature to preserve. Keep the `continue`-based structure removed; always report, always remember.

- [ ] **Step 2: Verify**

Run the orchestrator (`python main.py`) against a project with a known lockfile vulnerability (sample-app's existing fixture, if any, or temporarily add one) through two change batches; confirm in Mongo that `agent_memories` gains one `package`-subject `[finding]` memory per advisory and that the finding is still reported (not suppressed) on the second batch, printed to stdout and visible via `GET /api/projects/:id/findings`.

- [ ] **Step 3: Commit**

```bash
git add packages/orchestrator/main.py
git commit -m "fix(orchestrator): stop permanently suppressing re-seen dependency findings; dedup only ever applied to the dummy store's memory, not to real open vulnerabilities"
```

## Task 5: Branch-wide verification and push

**Files:** none (verification only)

- [ ] **Step 1: Confirm the dummy store is fully gone**

```bash
grep -rn "import memory\b\|memory\.already_found\|memory\.insert_one\|memory\.json" packages/orchestrator/*.py
```
Expected: no output.

- [ ] **Step 2: Full live run** — start the harness service (with real `.env` Mongo URI), sample-app, and Ollama; run `packages/orchestrator/.venv/bin/python packages/orchestrator/main.py`, then touch a file in `sample-app/src/routes/` to trigger a change. Confirm in the terminal output and in Mongo (`agent_runs`, `agent_events`, `agent_memories`) that a full investigate → recall → LLM decide → probe → remember → finish cycle ran with no exceptions and no `StoreUnavailableError`.

- [ ] **Step 3: Run the existing TypeScript test suite once more** (this plan doesn't touch `packages/service`, but confirms nothing there regressed):

```bash
cd packages/service && npx vitest run --reporter=dot
```
Expected: same baseline as before this plan (223 passed / 15 skipped, or whatever the current pre-existing-failure count is — not newly broken).

- [ ] **Step 4: Push**

```bash
git push origin feature/mongodb-storage
```
