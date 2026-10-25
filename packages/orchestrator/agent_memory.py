"""Real agent-memory client: the harness's Mongo-backed /api/projects/:id/agent/* API
(packages/service/src/agentMemory.ts), not a local stand-in.

Every stored memory's content is prefixed with a machine-readable verdict tag ("[clean] " or
"[finding] "), so "has this tool already cleared this exact subject" is a deterministic string
check in code — never something an LLM has to infer from prose.
"""
import requests

import harness

VERDICTS = {"clean", "finding"}


def _url(project_id: str, path: str) -> str:
    return f"{harness.HARNESS_HTTP}/api/projects/{project_id}/agent{path}"


def start_run(project_id: str, goal: str, subject: dict | None = None) -> dict:
    body = {"goal": goal}
    if subject is not None:
        body["subject"] = subject
    res = requests.post(_url(project_id, "/runs"), json=body, timeout=10)
    res.raise_for_status()
    return res.json()


def log_step(project_id: str, run_id: str, type: str, status: str = "ok", **kw) -> dict:
    """Append one episodic event to the run. Best-effort: a logging failure must never stop
    an investigation."""
    try:
        res = requests.post(_url(project_id, f"/runs/{run_id}/events"), json={"type": type, "status": status, **kw}, timeout=10)
        if res.status_code >= 400:
            print(f"[agent-memory] event rejected ({res.status_code}): {res.json().get('error')}")
            return {}
        return res.json()
    except requests.RequestException as e:
        print(f"[agent-memory] could not log step ({e})")
        return {}


def finish_run(project_id: str, run_id: str, status: str, **kw) -> dict:
    res = requests.post(_url(project_id, f"/runs/{run_id}/finish"), json={"status": status, **kw}, timeout=10)
    res.raise_for_status()
    return res.json()


def recall(project_id: str, subject_type: str, subject_key: str) -> list[dict]:
    """Active memories for this exact subject. The server filters by subject.key only, so
    filter subject.type here too in case another subject type ever reuses the same key text."""
    res = requests.get(_url(project_id, "/memories"), params={"subject": subject_key}, timeout=10)
    res.raise_for_status()
    memories = res.json()["memories"]
    return [m for m in memories if m.get("subject", {}).get("type") == subject_type]


def remember(project_id: str, run_id: str, subject_type: str, subject_key: str, verdict: str, note: str,
             confidence: str = "medium", evidence: list[dict] | None = None, ttl_hours: int | None = None) -> dict:
    if verdict not in VERDICTS:
        raise ValueError(f"verdict must be one of {VERDICTS}, got {verdict!r}")
    # The server marks an agent memory with no evidence "unverified" (excluded from recall() by
    # default) — the run that observed this verdict is itself evidence, so default to it.
    body = {
        "kind": "fact", "content": f"[{verdict}] {note}", "subject": {"type": subject_type, "key": subject_key},
        "evidence": evidence or [{"kind": "event", "id": run_id}], "confidence": confidence, "source": "agent", "createdByRun": run_id,
    }
    if ttl_hours is not None:
        body["ttlHours"] = ttl_hours
    try:
        res = requests.post(_url(project_id, "/memories"), json=body, timeout=10)
        if res.status_code >= 400:
            print(f"[agent-memory] memory rejected ({res.status_code}): {res.json().get('error')}")
            return {}
        return res.json()
    except requests.RequestException as e:
        print(f"[agent-memory] could not store memory ({e})")
        return {}


def already_clean(project_id: str, subject_type: str, subject_key: str) -> bool:
    """True iff the most recent active memory for this subject says verdict 'clean'.
    `recall` is already sorted by updatedAt desc, so the first clean/finding-tagged memory wins."""
    for m in recall(project_id, subject_type, subject_key):
        content = m.get("content", "")
        if content.startswith("[clean] "):
            return True
        if content.startswith("[finding] "):
            return False
    return False
