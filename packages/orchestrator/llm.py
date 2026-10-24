"""Thin client for the local Qwen model served by Ollama."""
import json
import requests

OLLAMA_URL = "http://127.0.0.1:11434/api/chat"
MODEL = "qwen3:4b-instruct-2507-q8_0"

TOOL_MENU = """Available tools:
- auth_probe: requests an endpoint with no auth header, flags if it still succeeds
- sqli_probe: sends a quote-breaking payload into a path param, flags a server crash
- secret_scan: greps source for hardcoded-secret-shaped strings
"""


def choose_tools(endpoint: dict) -> list[str]:
    """Ask the model which of the 3 tools are worth running against this changed endpoint.
    Falls back to running all three if the model is unreachable or answers oddly."""
    prompt = (
        f"{TOOL_MENU}\n"
        f"A code change was just detected affecting this endpoint: {endpoint['method']} {endpoint['path']}.\n"
        'Reply with ONLY a JSON array of tool names to run, e.g. ["auth_probe", "sqli_probe"]. '
        "Pick every tool that could plausibly apply; do not explain."
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
        valid = {"auth_probe", "sqli_probe", "secret_scan"}
        chosen = [n for n in names if n in valid]
        return chosen or list(valid)
    except (requests.RequestException, KeyError, ValueError, json.JSONDecodeError) as e:
        print(f"[llm] could not get a decision ({e}), running all tools")
        return ["auth_probe", "sqli_probe", "secret_scan"]
