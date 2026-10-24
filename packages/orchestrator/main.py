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

import harness
import llm
import memory
import tools
from llm import ENDPOINT_TOOLS, DEPENDENCY_TOOLS


def available_tools(project_id: str) -> list[str]:
    """Endpoint probes are always runnable; dependency scanners only if the harness reports them ready."""
    ready = {s["tool"] for s in harness.ready_scanners(project_id)}
    return sorted(ENDPOINT_TOOLS) + sorted(DEPENDENCY_TOOLS & ready)


def investigate(project_id: str, endpoint: dict, available: list[str]) -> None:
    print(f"\n=== change detected: {endpoint['method']} {endpoint['path']} ===")
    chosen = llm.choose_tools(endpoint, available)
    print(f"[llm] chose tools: {chosen}")

    # endpoint probes: one finding each, deduped per (tool, endpoint)
    for name in [c for c in chosen if c in ENDPOINT_TOOLS]:
        if memory.already_found(name, endpoint["path"]):
            print(f"[{name}] already reported for {endpoint['path']}, skipping")
            continue
        result = tools.TOOLS[name](endpoint)
        if result is None:
            print(f"[{name}] nothing found")
            continue
        saved = memory.insert_one(result)
        print(f"[{name}] FINDING: {saved['summary']} (severity={saved.get('severity')})")

    # dependency scanners: run the chosen real tools in one harness scan (project-wide, not per-endpoint)
    dep_tools = [c for c in chosen if c in DEPENDENCY_TOOLS]
    if dep_tools:
        print(f"[deps] running real scanners via harness: {dep_tools}")
        try:
            findings = tools.run_dependency_scanners(project_id, dep_tools)
        except Exception as e:  # harness refused, timed out, or Mongo unavailable
            print(f"[deps] scan failed: {e}")
            return
        if not findings:
            print("[deps] no dependency vulnerabilities reported")
        for f in findings:
            if memory.already_found(f["tool"], f["evidence"].get("advisoryId")):
                continue
            saved = memory.insert_one({**f, "endpoint": f["evidence"].get("advisoryId")})
            print(f"[{saved['tool']}] FINDING: {saved['summary']} (severity={saved.get('severity')})")


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
            dep_done = False
            for endpoint in endpoints:
                investigate(project_id, endpoint, available if not dep_done else [t for t in available if t in ENDPOINT_TOOLS])
                dep_done = True  # dependency scan is whole-project; run it only on the first endpoint


if __name__ == "__main__":
    asyncio.run(watch())
