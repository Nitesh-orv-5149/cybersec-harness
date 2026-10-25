"""Thin client for the harness service's HTTP API: project state, the live graph, and the real
dependency scanners (npm audit, OSV-Scanner, OSV.dev API, Trivy) the service runs and persists.

The orchestrator never runs those scanners itself — it asks the service to, so results land in the
same MongoDB as the graph and show up in the dashboard's Security view.
"""
import time
import requests

HARNESS_HTTP = "http://127.0.0.1:4318"
HARNESS_WS = "ws://127.0.0.1:4318/ws"

DEPENDENCY_FILES = {"package.json", "package-lock.json", "npm-shrinkwrap.json"}


def _url(project_id: str, path: str) -> str:
    return f"{HARNESS_HTTP}/api/projects/{project_id}{path}"


def project_id() -> str:
    projects = requests.get(f"{HARNESS_HTTP}/api/projects", timeout=5).json()
    if not projects:
        raise RuntimeError("no project registered on the harness — is it monitoring sample-app?")
    return projects[0]["id"]


def status(project_id: str) -> dict:
    return requests.get(_url(project_id, "/status"), timeout=5).json()


def graph_change(project_id: str) -> dict:
    """Read the latest graph revision and identify endpoints changed or affected by it."""
    graph_res = requests.get(_url(project_id, "/graph"), timeout=5).json()
    graph = graph_res.get("graph") or {}
    nodes = graph.get("nodes") or []
    endpoints = {n["id"]: n for n in nodes if n.get("kind") == "endpoint" and n.get("id")}
    changed_files = set(graph_res.get("lastChangedFiles") or [])
    last_diff = graph_res.get("lastDiff") or {}
    impact = graph_res.get("lastImpact") or {}

    affected_ids = set(impact.get("affectedEndpoints") or [])
    changed_ids = set(last_diff.get("addedNodes") or []) | set(last_diff.get("changedNodes") or [])
    selected_ids = affected_ids | (changed_ids & endpoints.keys())
    selected_ids.update(
        node_id for node_id, node in endpoints.items()
        if node.get("loc", {}).get("file") in changed_files
    )
    current_endpoints = {}
    for node_id, node in endpoints.items():
        meta = node.get("meta") or {}
        if meta.get("method") and meta.get("path"):
            current_endpoints[node_id] = {
                "id": node_id,
                "method": meta["method"],
                "path": meta["path"],
            }

    return {
        "graphVersion": graph_res.get("graphVersion"),
        "sourceHash": graph_res.get("sourceHash"),
        "changedFiles": sorted(changed_files),
        "endpoints": sorted(
            (current_endpoints[node_id] for node_id in selected_ids if node_id in current_endpoints),
            key=lambda e: (e["method"], e["path"], e["id"]),
        ),
        "_currentEndpoints": current_endpoints,
    }


def changed_endpoints(project_id: str) -> list[dict]:
    """Compatibility helper for callers that only need endpoint method/path pairs."""
    return [
        {"method": e["method"], "path": e["path"]}
        for e in graph_change(project_id)["endpoints"]
    ]


def log_event(project_id: str, type: str, title: str, *, endpoint: str | None = None,
              tool: str | None = None, severity: str | None = None, detail: str | None = None,
              data: dict | None = None) -> None:
    """Report one agent-activity event to the harness so it shows up in the dashboard's AI agent tab.
    Best-effort: a logging failure must never stop the investigation."""
    payload = {"type": type, "title": title, "endpoint": endpoint, "tool": tool,
               "severity": severity, "detail": detail, "data": data}
    try:
        requests.post(_url(project_id, "/agent/events"), json=payload, timeout=5)
    except requests.RequestException as e:
        print(f"[agent-log] could not report event ({e})")


def ready_scanners(project_id: str) -> list[dict]:
    """Dependency scanners the service reports as usable right now (installed, working, network allowed)."""
    scanners = requests.get(_url(project_id, "/security/scanners"), timeout=30).json()
    return [s for s in scanners if s.get("state") == "ready"]


def run_dependency_scan(project_id: str, tools: list[str], timeout_s: int = 300) -> dict:
    """Start a scan restricted to `tools`, wait for it to finish, and return {run, observations}."""
    while True:
        res = requests.post(
            _url(project_id, "/security/dependency-scans"),
            json={"tools": tools, "trigger": "agent"},
            timeout=10,
        )
        if res.status_code == 202:
            break
        if res.status_code != 409:
            raise RuntimeError(f"harness refused the scan (HTTP {res.status_code}): {res.text[:200]}")
        wait_deadline = time.monotonic() + timeout_s
        while time.monotonic() < wait_deadline:
            if not status(project_id).get("security", {}).get("dependencies", {}).get("job"):
                break
            time.sleep(3)
        else:
            raise RuntimeError(f"timed out waiting for the current dependency scan after {timeout_s}s")
    run_id = res.json()["runId"]
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        time.sleep(3)
        result = requests.get(_url(project_id, f"/security/dependency-scans/{run_id}"), timeout=10).json()
        if result["run"]["status"] != "running":
            return result
    raise RuntimeError(f"scan {run_id} still running after {timeout_s}s")
