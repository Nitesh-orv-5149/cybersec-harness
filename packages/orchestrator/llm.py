"""Thin client for OpenAI or the local Qwen model served by Ollama."""
import json
import os
import requests

OLLAMA_URL = "http://127.0.0.1:11434/api/chat"
OPENAI_URL = "https://api.openai.com/v1/chat/completions"
OLLAMA_MODEL = "qwen3:4b-instruct-2507-q8_0"
OPENAI_MODEL = os.getenv("OPENAI_MODEL", "gpt-4o-mini")

# Endpoint probes run locally against the running sample-app; dependency scanners are the real
# tools the harness service runs against the project's lockfile and persists.
ENDPOINT_TOOLS = {"auth_probe", "sqli_probe", "secret_scan"}
DEPENDENCY_TOOLS = {"osv-api", "npm-audit", "osv-scanner", "trivy"}

TOOL_MENU = """Endpoint probes (run against the changed HTTP endpoint):
- auth_probe: requests the endpoint with no auth header, flags if it still succeeds
- sqli_probe: sends a quote-breaking payload into a path param, flags a server crash
- secret_scan: greps source for hardcoded-secret-shaped strings

Dependency vulnerability scanners run automatically on every latest graph revision, independently
of this endpoint-tool choice.
"""


def choose_tools(endpoint: dict, available: list[str]) -> tuple[list[str], str]:
    """Ask the configured model which available tools are worth running for this change.
    `available` is the set the orchestrator can actually run right now (ready scanners + probes).
    Returns (chosen_tools, reason). OpenAI is used when OPENAI_API_KEY is set; otherwise Ollama
    is used. If the configured model is unreachable or unusable, all available tools are run."""
    prompt = (
        f"{TOOL_MENU}\n"
        f"A code change was just detected affecting this endpoint: {endpoint['method']} {endpoint['path']}.\n"
        f"Only these tools are available right now: {available}.\n"
        'Reply with ONLY a JSON array of tool names to run, e.g. ["auth_probe", "osv-api"]. '
        "Pick every available tool that could plausibly apply; do not explain."
    )
    api_key = os.getenv("OPENAI_API_KEY")
    if api_key:
        provider = "OpenAI"
        model = OPENAI_MODEL
        url = OPENAI_URL
        headers = {"Authorization": f"Bearer {api_key}"}
        payload = {"model": model, "messages": [{"role": "user", "content": prompt}]}
    else:
        provider = "Ollama"
        model = OLLAMA_MODEL
        url = OLLAMA_URL
        headers = {}
        payload = {
            "model": model,
            "messages": [{"role": "user", "content": prompt}],
            "stream": False,
        }
    try:
        res = requests.post(url, headers=headers, json=payload, timeout=30)
        res.raise_for_status()
        response = res.json()
        content = (
            response["choices"][0]["message"]["content"]
            if provider == "OpenAI"
            else response["message"]["content"]
        )
        names = json.loads(content[content.index("["): content.rindex("]") + 1])
        chosen = [n for n in names if n in available]
        if chosen:
            return chosen, f"llm: {provider} ({model})"
        return list(available), f"fallback: {provider} ({model}) returned no valid tool names"
    except (requests.RequestException, KeyError, ValueError, json.JSONDecodeError) as e:
        print(f"[llm] {provider} decision failed ({type(e).__name__}), running all available tools")
        return list(available), f"fallback: {provider} request failed ({type(e).__name__})"
