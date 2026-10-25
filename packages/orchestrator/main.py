"""Orchestrator: automatically checks graph-affected endpoints and ready dependency scanners.

Two kinds of tool are available:
  - endpoint probes (auth_probe, sqli_probe, secret_scan): run here against the running sample-app
  - dependency scanners (osv-api, npm-audit, osv-scanner, trivy): run by the harness service against
    the project's lockfile, so results are persisted in MongoDB and shown in the dashboard

Endpoint probes are selected by the configured model. Dependency scans run all scanners the harness
currently reports as ready, independently of whether an endpoint changed.

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


def investigate_endpoint(project_id: str, endpoint: dict) -> None:
    ep = f"{endpoint['method']} {endpoint['path']}"
    print(f"\n=== change detected: {ep} ===")
    available = sorted(ENDPOINT_TOOLS)
    chosen, reason = llm.choose_tools(endpoint, available)
    print(f"[llm] chose tools: {chosen} ({reason})")
    harness.log_event(project_id, "decision", f"Chose {len(chosen)} tool(s) for {ep}",
                      endpoint=ep, detail=reason, data={"available": available, "chosen": chosen, "reason": reason})

    # Re-run checks for each graph revision; old findings must not suppress future checks.
    for name in [c for c in chosen if c in ENDPOINT_TOOLS]:
        try:
            result = tools.TOOLS[name](endpoint)
        except Exception as e:
            print(f"[{name}] check failed ({type(e).__name__}): {e}")
            harness.log_event(
                project_id, "tool_result", f"{name}: check failed ({type(e).__name__})",
                endpoint=ep, tool=name, data={"status": "failed", "error": str(e)},
            )
            continue
        if result is None:
            print(f"[{name}] nothing found")
            harness.log_event(project_id, "tool_result", f"{name}: nothing found",
                              endpoint=ep, tool=name, data={"status": "clean"})
            continue
        if result.get("error"):
            harness.log_event(
                project_id, "tool_result", f"{name}: target check failed",
                endpoint=ep, tool=name,
                data={"status": "failed", "error": result["error"]},
            )
            continue
        saved = memory.upsert_one(result)
        print(f"[{name}] FINDING: {saved['summary']} (severity={saved.get('severity')})")
        harness.log_event(project_id, "tool_result", f"{name}: {saved['summary']}",
                          endpoint=ep, tool=name, severity=saved.get("severity"),
                          data={"status": "finding", **saved})

def scan_dependencies(project_id: str, change: dict) -> None:
    ready = harness.ready_scanners(project_id)
    dep_tools = sorted({s["tool"] for s in ready} & DEPENDENCY_TOOLS)
    if not dep_tools:
        harness.log_event(
            project_id, "scan", "Automatic dependency scan skipped: no scanners are ready",
            data={"status": "skipped", "reason": "no_ready_scanners", **change},
        )
        return

    print(f"[deps] scanning latest graph revision with {dep_tools}")
    harness.log_event(
        project_id, "scan", f"Automatically scanning dependencies: {', '.join(dep_tools)}",
        data={"status": "running", "tools": dep_tools, **change},
    )
    try:
        findings = tools.run_dependency_scanners(project_id, dep_tools)
    except Exception as e:
        print(f"[deps] scan failed: {e}")
        harness.log_event(
            project_id, "scan", f"Automatic dependency scan failed: {type(e).__name__}",
            tool=",".join(dep_tools),
            data={"status": "failed", "error": str(e), "tools": dep_tools, **change},
        )
        return

    for finding in findings:
        saved = memory.upsert_one(finding)
        print(f"[{saved['tool']}] FINDING: {saved['summary']} (severity={saved.get('severity')})")
        harness.log_event(
            project_id, "tool_result", f"{saved['tool']}: {saved['summary']}",
            tool=saved["tool"], severity=saved.get("severity"),
            data={"status": "finding", **saved},
        )
    status = "findings" if findings else "clean"
    harness.log_event(
        project_id, "scan", f"Automatic dependency scan completed: {len(findings)} finding(s)",
        tool=",".join(dep_tools),
        data={"status": status, "total": len(findings), "tools": dep_tools, **change},
    )


def scan_graph_change(project_id: str, change: dict) -> None:
    endpoints = change["endpoints"]
    labels = [f"{e['method']} {e['path']}" for e in endpoints]
    harness.log_event(
        project_id, "change", f"Graph changed at version {change.get('graphVersion')}",
        detail=", ".join(labels) if labels else "No endpoint directly affected",
        data={
            "endpoints": endpoints,
            "changedFiles": change["changedFiles"],
            "graphVersion": change.get("graphVersion"),
            "sourceHash": change.get("sourceHash"),
        },
    )
    for endpoint in endpoints:
        investigate_endpoint(project_id, endpoint)
    scan_dependencies(project_id, change)


async def process_changes(project_id: str, queue: asyncio.Queue) -> None:
    while True:
        change = await queue.get()
        pending = [change]
        try:
            await asyncio.sleep(0.5)
            while True:
                try:
                    pending.append(queue.get_nowait())
                except asyncio.QueueEmpty:
                    break
            latest = pending[-1]
            changed_ids = {
                e["id"] for item in pending for e in item["endpoints"] if e.get("id")
            }
            current_endpoints = latest.get("_currentEndpoints", {})
            if "_currentEndpoints" in latest:
                endpoints = [
                    current_endpoints[node_id]
                    for node_id in changed_ids if node_id in current_endpoints
                ]
            else:
                endpoints = {
                    (e["method"], e["path"]): e
                    for item in pending for e in item["endpoints"]
                }.values()
            latest["endpoints"] = sorted(
                endpoints, key=lambda e: (e["method"], e["path"])
            )
            latest.pop("_currentEndpoints", None)
            latest["changedFiles"] = sorted({
                file for item in pending for file in item["changedFiles"]
            })
            await asyncio.to_thread(scan_graph_change, project_id, latest)
        except Exception as e:
            print(f"[agent] graph-change scan failed ({type(e).__name__}): {e}")
            harness.log_event(
                project_id, "scan", f"Automatic graph-change scan failed: {type(e).__name__}",
                data={"status": "failed"},
            )
        finally:
            for _ in pending:
                queue.task_done()


async def watch():
    project_id = harness.project_id()
    print(f"watching project {project_id} via {harness.HARNESS_WS}")
    queue = asyncio.Queue()
    worker = asyncio.create_task(process_changes(project_id, queue))
    last_revision = None
    try:
        async with websockets.connect(harness.HARNESS_WS) as ws:
            async for raw in ws:
                msg = json.loads(raw)
                if msg.get("kind") != "graph":
                    continue
                try:
                    change = await asyncio.to_thread(harness.graph_change, project_id)
                except Exception as e:
                    print(f"[harness] could not read graph revision ({type(e).__name__}): {e}")
                    continue
                revision = change.get("graphVersion") or change.get("sourceHash")
                if not revision or revision == last_revision:
                    continue
                last_revision = revision
                print(
                    f"[harness] graph revision {change.get('graphVersion')}: "
                    f"{len(change['endpoints'])} affected endpoint(s), "
                    f"{len(change['changedFiles'])} changed file(s)"
                )
                await queue.put(change)
    finally:
        worker.cancel()
        await asyncio.gather(worker, return_exceptions=True)


if __name__ == "__main__":
    asyncio.run(watch())
