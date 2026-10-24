"""Thin client for the harness service's HTTP API: project state, the live graph, and the real
dependency scanners (npm audit, OSV-Scanner, OSV.dev API, Trivy) the service runs and persists.

The orchestrator never runs those scanners itself — it asks the service to, so results land in the
same MongoDB as the graph and show up in the dashboard's Security view.
"""
import time
import requests

HARNESS_HTTP = "http://127.0.0.1:4317"
HARNESS_WS = "ws://127.0.0.1:4317/ws"

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


def changed_endpoints(project_id: str) -> list[dict]:
    """Endpoint nodes whose source file is in the harness's most recent change set."""
    graph_res = requests.get(_url(project_id, "/graph"), timeout=5).json()
    changed_files = set(graph_res.get("lastChangedFiles") or [])
    graph = graph_res.get("graph")
    if not changed_files or not graph:
        return []
    return [
        {"method": n["meta"]["method"], "path": n["meta"]["path"]}
        for n in graph["nodes"]
        if n.get("kind") == "endpoint" and n.get("loc", {}).get("file") in changed_files
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
    res = requests.post(_url(project_id, "/security/dependency-scans"), json={"tools": tools, "trigger": "agent"}, timeout=10)
    if res.status_code != 202:
        raise RuntimeError(f"harness refused the scan (HTTP {res.status_code}): {res.text[:200]}")
    run_id = res.json()["runId"]
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        time.sleep(3)
        result = requests.get(_url(project_id, f"/security/dependency-scans/{run_id}"), timeout=10).json()
        if result["run"]["status"] != "running":
            return result
    raise RuntimeError(f"scan {run_id} still running after {timeout_s}s")
