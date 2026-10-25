"""Thin client for the local Qwen model served by Ollama."""
import json
import requests

OLLAMA_URL = "http://127.0.0.1:11434/api/chat"
MODEL = "qwen3:4b-instruct-2507-q8_0"

# Endpoint probes run locally against the running sample-app; dependency scanners are the real
# tools the harness service runs against the project's lockfile and persists.
ENDPOINT_TOOLS = {"auth_probe", "sqli_probe", "secret_scan"}
DEPENDENCY_TOOLS = {"osv-api", "npm-audit", "osv-scanner", "trivy"}

TOOL_MENU = """Endpoint probes (run against the changed HTTP endpoint):
- auth_probe: requests the endpoint with no auth header, flags if it still succeeds
- sqli_probe: sends a quote-breaking payload into a path param, flags a server crash
- secret_scan: greps source for hardcoded-secret-shaped strings

Dependency vulnerability scanners (run against the project's package-lock.json):
- osv-api: queries the OSV.dev advisory database for known-vulnerable package versions
- npm-audit: runs `npm audit` against the registry's advisory endpoint
- osv-scanner: runs the OSV-Scanner binary over the lockfile
- trivy: runs Trivy's vulnerability scanner over the dependency tree
"""


def _memory_block(memories: list[dict]) -> str:
    """Render recalled [finding]-tagged memories as lines that name the exact tool each one is
    about, parsed from subject.key ("<tool>|<method> <path>") — never left for the model to
    infer from prose, since that's exactly how a live test found it misattributing memories."""
    if not memories:
        return ""
    lines = []
    for m in memories:
        tool = m["subject"]["key"].split("|", 1)[0]
        text = m["content"].removeprefix("[finding] ")
        lines.append(f"- {tool}: finding — {text}")
    return (
        "\nMemory from earlier runs on this endpoint (each line names the exact tool it's about):\n"
        + "\n".join(lines)
        + "\nThese are past findings, not guarantees they still reproduce — re-run them if you think "
        "they're still relevant; this is just context, not an instruction to skip.\n"
    )


def choose_tools(endpoint: dict, available: list[str], memories: list[dict] | None = None) -> tuple[list[str], str]:
    """Ask the model which of the currently-available tools are worth running for this change.
    `available` is the set the orchestrator can actually run right now (ready scanners + probes).
    `memories` are past [finding] memories for tools in `available` that are NOT deterministically
    clean (that filtering happens in the caller) — informational context, not a skip instruction.
    Returns (chosen_tools, reason). `reason` is "llm: <model>" on a real decision, or a
    "fallback: ..." string when the model was unreachable/unusable and all tools are run."""
    prompt = (
        f"{TOOL_MENU}{_memory_block(memories or [])}\n"
        f"A code change was just detected affecting this endpoint: {endpoint['method']} {endpoint['path']}.\n"
        f"Only these tools are available right now: {available}.\n"
        'Reply with ONLY a JSON array of tool names to run, e.g. ["auth_probe", "osv-api"]. '
        "Pick every available tool that could plausibly apply; do not explain."
    )
    try:
        res = requests.post(
            OLLAMA_URL,
            json={"model": MODEL, "messages": [{"role": "user", "content": prompt}], "stream": False},
            timeout=30,
        )
        res.raise_for_status()
        content = res.json()["message"]["content"]
        names = json.loads(content[content.index("["): content.rindex("]") + 1])
        chosen = [n for n in names if n in available]
        if chosen:
            return chosen, f"llm: {MODEL}"
        return list(available), f"fallback: {MODEL} returned no valid tool names"
    except (requests.RequestException, KeyError, ValueError, json.JSONDecodeError) as e:
        print(f"[llm] could not get a decision ({e}), running all available tools")
        return list(available), f"fallback: model unreachable ({type(e).__name__})"
