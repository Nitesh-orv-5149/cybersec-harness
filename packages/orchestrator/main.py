"""LLM orchestrator: watches the harness's live graph for changes, asks a local Qwen
model which dummy cybersec tools to run against the affected endpoint(s), runs them
against the running sample-app, and records findings in the dummy JSON memory store.

No containers, no new infra beyond the harness/sample-app that are already running
host-direct. Run with: packages/orchestrator/.venv/bin/python packages/orchestrator/main.py
"""
import asyncio
import json
import requests
import websockets

import llm
import memory
import tools

HARNESS_HTTP = "http://127.0.0.1:4317"
HARNESS_WS = "ws://127.0.0.1:4317/ws"


def get_project_id() -> str:
    projects = requests.get(f"{HARNESS_HTTP}/api/projects", timeout=5).json()
    if not projects:
        raise RuntimeError("no project registered on the harness — is it monitoring sample-app?")
    return projects[0]["id"]


def changed_endpoints(project_id: str) -> list[dict]:
    """Endpoint nodes whose source file is in the most recent change set."""
    graph_res = requests.get(f"{HARNESS_HTTP}/api/projects/{project_id}/graph", timeout=5).json()
    changed_files = set(graph_res.get("lastChangedFiles") or [])
    if not changed_files or not graph_res.get("graph"):
        return []
    endpoints = []
    for node in graph_res["graph"]["nodes"]:
        if node.get("kind") == "endpoint" and node.get("loc", {}).get("file") in changed_files:
            endpoints.append({"method": node["meta"]["method"], "path": node["meta"]["path"]})
    return endpoints


def investigate(endpoint: dict) -> None:
    print(f"\n=== change detected: {endpoint['method']} {endpoint['path']} ===")
    chosen = llm.choose_tools(endpoint)
    print(f"[llm] chose tools: {chosen}")
    for name in chosen:
        if memory.already_found(name, endpoint["path"]):
            print(f"[{name}] already reported for {endpoint['path']}, skipping")
            continue
        result = tools.TOOLS[name](endpoint)
        if result is None:
            print(f"[{name}] nothing found")
            continue
        saved = memory.insert_one(result)
        print(f"[{name}] FINDING: {saved['summary']} (severity={saved.get('severity')})")


async def watch():
    project_id = get_project_id()
    print(f"watching project {project_id} via {HARNESS_WS}")
    async with websockets.connect(HARNESS_WS) as ws:
        async for raw in ws:
            msg = json.loads(raw)
            if msg.get("kind") != "graph":
                continue
            for endpoint in changed_endpoints(project_id):
                investigate(endpoint)


if __name__ == "__main__":
    asyncio.run(watch())
