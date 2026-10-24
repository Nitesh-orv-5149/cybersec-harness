"""Endpoint probes: lightweight checks the orchestrator runs directly against the running
sample-app. These are not real scanners — they prove the per-endpoint orchestration wiring.
The real dependency-vulnerability scanners (OSV, npm audit, Trivy) are run by the harness
service via harness.run_dependency_scan, not from here.
"""
import re
import pathlib
import requests

import harness

SAMPLE_APP_URL = "http://127.0.0.1:3000"
SAMPLE_APP_SRC = pathlib.Path(__file__).parent.parent.parent / "sample-app" / "src"

TOOLS = {}


def tool(name):
    def register(fn):
        TOOLS[name] = fn
        return fn
    return register


@tool("auth_probe")
def auth_probe(endpoint: dict) -> dict | None:
    """Request an endpoint without the x-demo-user auth header; flag if it still succeeds."""
    method, path = endpoint["method"], endpoint["path"]
    probe_path = re.sub(r":id|\{id\}", "1", path)
    try:
        res = requests.request(method, SAMPLE_APP_URL + probe_path, timeout=3)
    except requests.RequestException as e:
        return {"tool": "auth_probe", "endpoint": path, "error": str(e)}
    if res.status_code != 200:
        return None
    severity = "medium" if method != "GET" else "low"
    return {
        "tool": "auth_probe",
        "endpoint": path,
        "severity": severity,
        "summary": f"{method} {path} returned 200 with no auth header",
        "evidence": {"status": res.status_code, "method": method},
    }


@tool("sqli_probe")
def sqli_probe(endpoint: dict) -> dict | None:
    """Send a quote-breaking payload into a path param; flag an unhandled 500 (likely an
    unsanitized string reaching a query/parser), not a confirmed injection."""
    path = endpoint["path"]
    if ":id" not in path and "{id}" not in path:
        return None
    probe_path = re.sub(r":id|\{id\}", "1' OR '1'='1", path)
    try:
        res = requests.get(SAMPLE_APP_URL + probe_path, timeout=3)
    except requests.RequestException as e:
        return {"tool": "sqli_probe", "endpoint": path, "error": str(e)}
    if res.status_code != 500:
        return None
    return {
        "tool": "sqli_probe",
        "endpoint": path,
        "severity": "high",
        "summary": f"GET {probe_path} crashed with 500 — unsanitized input likely reaching a query",
        "evidence": {"status": res.status_code, "payload": probe_path},
    }


@tool("secret_scan")
def secret_scan(endpoint: dict) -> dict | None:
    """Grep the source tree for hardcoded-secret-shaped string literals."""
    pattern = re.compile(r"(password|secret|api[_-]?key|token)\s*[:=]\s*['\"][^'\"]{3,}['\"]", re.I)
    hits = []
    for f in SAMPLE_APP_SRC.rglob("*.js"):
        for i, line in enumerate(f.read_text().splitlines(), start=1):
            if pattern.search(line):
                hits.append(f"{f.relative_to(SAMPLE_APP_SRC.parent)}:{i}")
    if not hits:
        return None
    return {
        "tool": "secret_scan",
        "endpoint": endpoint["path"],
        "severity": "medium",
        "summary": f"{len(hits)} hardcoded-secret-shaped string(s) found in source",
        "evidence": {"locations": hits},
    }


def run_dependency_scanners(project_id: str, tools: list[str]) -> list[dict]:
    """Ask the harness to run the given real scanners against the project's lockfile, then turn each
    advisory observation into a finding record. One scan may return many findings (one per advisory).
    The harness persists the full run in MongoDB; these records are the orchestrator's own memory copy."""
    result = harness.run_dependency_scan(project_id, tools)
    run, observations = result["run"], result.get("observations") or []
    findings = []
    for obs in observations:
        findings.append({
            "tool": obs.get("tool"),
            "endpoint": "(dependency)",
            "severity": obs.get("severity"),
            "summary": f"{obs.get('packageName')}@{obs.get('installedVersion')}: {obs.get('advisoryId')} ({obs.get('title') or 'no title'})",
            "evidence": {
                "advisoryId": obs.get("advisoryId"),
                "package": obs.get("packageName"),
                "installedVersion": obs.get("installedVersion"),
                "fixedVersions": obs.get("fixedVersions"),
                "url": obs.get("url"),
                "runId": run.get("_id"),
            },
        })
    return findings
