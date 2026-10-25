"""LLM orchestrator: watches the harness's live graph for changes, asks a local Qwen model which
cybersec tools to run for the affected endpoint(s), runs them, and records findings in the dummy
JSON memory store.

Two kinds of tool are available:
  - endpoint probes (auth_probe, sqli_probe, secret_scan): run here against the running sample-app
  - dependency scanners (osv-api, npm-audit, osv-scanner, trivy): run by the harness service against
    the project's lockfile, so results are persisted in MongoDB and shown in the dashboard

The model only chooses from scanners the harness currently reports as ready, so it can't pick a tool
that isn't installed or reachable.

No containers, no new infra beyond the harness/sample-app that are already running host-direct.
Run with: packages/orchestrator/.venv/bin/python packages/orchestrator/main.py
"""
import asyncio
import json
import websockets

import agent_memory
import harness
import llm
import tools
from llm import ENDPOINT_TOOLS, DEPENDENCY_TOOLS


def available_tools(project_id: str) -> list[str]:
    """Endpoint probes are always runnable; dependency scanners only if the harness reports them ready."""
    ready = {s["tool"] for s in harness.ready_scanners(project_id)}
    return sorted(ENDPOINT_TOOLS) + sorted(DEPENDENCY_TOOLS & ready)


def investigate(project_id: str, endpoint: dict, available: list[str], run_deps: bool) -> None:
    ep = f"{endpoint['method']} {endpoint['path']}"
    print(f"\n=== change detected: {ep} ===")

    # Deterministic skip: a tool with an active [clean] memory for this exact endpoint is never
    # re-asked about — this is a code-level gate, not something left to the LLM's judgment (a
    # live test found the LLM does not reliably map a memory's prose back to the right tool).
    candidate_probe_tools = []
    for name in sorted(ENDPOINT_TOOLS & set(available)):
        key = f"{name}|{ep}"
        if agent_memory.already_clean(project_id, "endpoint", key):
            print(f"[{name}] already clean for {ep} (memory), skipping")
            harness.log_event(project_id, "tool_result", f"{name}: skipped (memory: already clean)",
                              endpoint=ep, tool=name, data={"status": "skipped"})
        else:
            candidate_probe_tools.append(name)
    available = [t for t in available if t not in (ENDPOINT_TOOLS - set(candidate_probe_tools))]

    run = agent_memory.start_run(project_id, f"Investigate {ep}", subject={"endpointPath": endpoint["path"]})
    memories = []
    for name in candidate_probe_tools:
        memories += [m for m in agent_memory.recall(project_id, "endpoint", f"{name}|{ep}") if m["content"].startswith("[finding]")]
    agent_memory.log_step(project_id, run["_id"], "memory_read", outputSummary=f"{len(memories)} finding memory(ies) recalled")

    chosen, reason = llm.choose_tools(endpoint, available, memories)
    print(f"[llm] chose tools: {chosen} ({reason})")
    agent_memory.log_step(project_id, run["_id"], "decision", outputSummary=f"chose {chosen} ({reason})")
    harness.log_event(project_id, "decision", f"Chose {len(chosen)} tool(s) for {ep}",
                      endpoint=ep, detail=reason, data={"available": available, "chosen": chosen, "reason": reason})

    # endpoint probes: record every outcome as a memory, clean or finding
    for name in [c for c in chosen if c in ENDPOINT_TOOLS]:
        key = f"{name}|{ep}"
        result = tools.TOOLS[name](endpoint)
        if result is None:
            print(f"[{name}] nothing found")
            agent_memory.remember(project_id, run["_id"], "endpoint", key, "clean", "ran, nothing found", ttl_hours=24 * 7)
            agent_memory.log_step(project_id, run["_id"], "tool_call", tool=name, status="ok", outputSummary="clean")
            harness.log_event(project_id, "tool_result", f"{name}: nothing found",
                              endpoint=ep, tool=name, data={"status": "clean"})
            continue
        agent_memory.remember(project_id, run["_id"], "endpoint", key, "finding", result["summary"],
                               confidence="medium", evidence=[{"kind": "event", "id": run["_id"]}])
        agent_memory.log_step(project_id, run["_id"], "tool_call", tool=name, status="ok", outputSummary=result["summary"])
        print(f"[{name}] FINDING: {result['summary']} (severity={result.get('severity')})")
        harness.log_event(project_id, "tool_result", f"{name}: {result['summary']}",
                          endpoint=ep, tool=name, severity=result.get("severity"),
                          data={"status": "finding", **result})

    agent_memory.finish_run(project_id, run["_id"], "completed", summary=f"ran {chosen}")

    # dependency scanners: run the chosen real tools in one harness scan (project-wide, not per-endpoint)
    dep_tools = [c for c in chosen if c in DEPENDENCY_TOOLS]
    if dep_tools and not run_deps:
        print(f"[deps] {dep_tools} already scanned this change batch, skipping")
        return
    if dep_tools:
        print(f"[deps] running real scanners via harness: {dep_tools}")
        harness.log_event(project_id, "scan", f"Running real scanners: {', '.join(dep_tools)}",
                          endpoint=ep, data={"tools": dep_tools})
        try:
            findings = tools.run_dependency_scanners(project_id, dep_tools)
        except Exception as e:  # harness refused, timed out, or Mongo unavailable
            print(f"[deps] scan failed: {e}")
            harness.log_event(project_id, "scan", f"Dependency scan failed: {e}",
                              tool=",".join(dep_tools), data={"status": "failed", "error": str(e)})
            return
        if not findings:
            print("[deps] no dependency vulnerabilities reported")
            harness.log_event(project_id, "scan", f"{', '.join(dep_tools)}: no dependency vulnerabilities",
                              data={"status": "clean", "tools": dep_tools})
        new = 0
        for f in findings:
            if memory.already_found(f["tool"], f["evidence"].get("advisoryId")):
                continue
            saved = memory.insert_one({**f, "endpoint": f["evidence"].get("advisoryId")})
            new += 1
            print(f"[{saved['tool']}] FINDING: {saved['summary']} (severity={saved.get('severity')})")
            harness.log_event(project_id, "tool_result", f"{saved['tool']}: {saved['summary']}",
                              tool=saved["tool"], severity=saved.get("severity"),
                              data={"status": "finding", **saved})
        if findings and new:
            harness.log_event(project_id, "scan", f"Dependency scan reported {new} new finding(s)",
                              data={"status": "findings", "new": new, "total": len(findings), "tools": dep_tools})


async def watch():
    project_id = harness.project_id()
    print(f"watching project {project_id} via {harness.HARNESS_WS}")
    # dependency scans are project-wide, so only run them once per change batch, not per endpoint
    async with websockets.connect(harness.HARNESS_WS) as ws:
        async for raw in ws:
            msg = json.loads(raw)
            if msg.get("kind") != "graph":
                continue
            endpoints = harness.changed_endpoints(project_id)
            if not endpoints:
                continue
            available = available_tools(project_id)
            print(f"[harness] available tools: {available}")
            eps = ", ".join(f"{e['method']} {e['path']}" for e in endpoints)
            harness.log_event(project_id, "change", f"Change affected {len(endpoints)} endpoint(s)",
                              detail=eps, data={"endpoints": endpoints, "availableTools": available})
            # dependency scan is whole-project, so run it only once per change batch (on the first endpoint)
            for i, endpoint in enumerate(endpoints):
                investigate(project_id, endpoint, available, run_deps=(i == 0))


if __name__ == "__main__":
    asyncio.run(watch())
