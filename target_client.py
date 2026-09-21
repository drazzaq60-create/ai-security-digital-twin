# target_client.py
# Calls a LIVE chatbot/LLM API endpoint so the red-team agent can attack a real deployed
# bot (black-box), not just a system prompt simulated on Gemini.
#
# SECURITY: the endpoint URL is user-supplied and the backend fetches it, which is a classic
# SSRF vector on a public instance. _guard_url() blocks non-http(s) schemes and any host that
# resolves to a private / loopback / link-local / reserved address (incl. cloud metadata).
# Set SENTINEL_ALLOW_PRIVATE_TARGETS=1 ONLY for local dev to allow localhost targets.

import ipaddress
import json
import os
import socket
import urllib.error
import urllib.request
from urllib.parse import urlparse

ALLOW_PRIVATE = os.getenv("SENTINEL_ALLOW_PRIVATE_TARGETS") == "1"
TIMEOUT = 25          # seconds per request to the target
MAX_REPLY = 4000      # cap the target's reply length


class TargetError(Exception):
    """Raised for a bad/blocked endpoint or a failed request (caught + surfaced, never crashes)."""


def _is_blocked_ip(ip: str) -> bool:
    o = ipaddress.ip_address(ip)
    return o.is_private or o.is_loopback or o.is_link_local or o.is_reserved or o.is_multicast or o.is_unspecified


def guard_url(url: str):
    """Reject non-http(s) or any host resolving to an internal address (SSRF protection)."""
    u = urlparse(url or "")
    if u.scheme not in ("http", "https"):
        raise TargetError("Endpoint URL must start with http:// or https://")
    host = u.hostname
    if not host:
        raise TargetError("Endpoint URL has no host")
    if ALLOW_PRIVATE:
        return
    try:
        infos = socket.getaddrinfo(host, None)
    except Exception as e:
        raise TargetError(f"Cannot resolve endpoint host: {e}")
    for info in infos:
        ip = info[4][0]
        if _is_blocked_ip(ip):
            raise TargetError("Endpoint resolves to a private/internal address (blocked for safety)")


def _dig(obj, path: str):
    """Follow a dotted path like 'choices.0.message.content' through dicts/lists."""
    cur = obj
    for part in path.split("."):
        try:
            cur = cur[int(part)] if isinstance(cur, list) else cur.get(part)
        except (KeyError, IndexError, ValueError, AttributeError, TypeError):
            return None
        if cur is None:
            return None
    return cur


def build_request(config: dict, attack_prompt: str):
    """Turn the endpoint config + one attack into (url, headers, body_dict, response_path)."""
    url = config.get("url", "")
    preset = (config.get("preset") or "openai").lower()
    headers = {"Content-Type": "application/json"}

    if preset == "openai":  # OpenAI-compatible: OpenAI, Groq, Together, many self-hosted
        key = config.get("api_key")
        if key:
            headers["Authorization"] = f"Bearer {key}"
        body = {
            "model": config.get("model") or "gpt-4o-mini",
            "messages": [{"role": "user", "content": attack_prompt}],
        }
        response_path = "choices.0.message.content"
    else:  # custom: user gives a JSON body template with {{prompt}} + a response path
        for h in (config.get("headers") or []):
            if h.get("name"):
                headers[h["name"]] = h.get("value", "")
        tmpl = config.get("body_template") or '{"message": "{{prompt}}"}'
        # json.dumps(...)[1:-1] = the attack escaped for placement inside a JSON string
        safe = json.dumps(attack_prompt)[1:-1]
        try:
            body = json.loads(tmpl.replace("{{prompt}}", safe))
        except Exception as e:
            raise TargetError(f"Custom body template isn't valid JSON after inserting the prompt: {e}")
        response_path = config.get("response_path") or ""
    return url, headers, body, response_path


def query_endpoint(config: dict, attack_prompt: str) -> str:
    """Send one attack to the live target and return its reply text. Raises TargetError on
    a blocked/unreachable endpoint; returns a best-effort string otherwise."""
    guard_url(config.get("url", ""))
    url, headers, body, response_path = build_request(config, attack_prompt)
    data = json.dumps(body).encode("utf-8")
    req = urllib.request.Request(url, data=data, headers=headers, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT) as resp:
            raw = resp.read().decode("utf-8", "ignore")
    except urllib.error.HTTPError as e:                # 4xx/5xx: still read the body
        raw = (e.read().decode("utf-8", "ignore") if e.fp else f"HTTP {e.code}")
    except Exception as e:
        raise TargetError(f"Request to target failed: {e}")

    try:
        parsed = json.loads(raw)
    except Exception:
        return raw[:MAX_REPLY]                          # target returned plain text

    if response_path:
        val = _dig(parsed, response_path)
        if val is not None:
            return str(val)[:MAX_REPLY]
    for p in ("choices.0.message.content", "choices.0.text", "message", "reply",
              "response", "output", "content", "answer", "text"):
        val = _dig(parsed, p)
        if val is not None:
            return str(val)[:MAX_REPLY]
    return json.dumps(parsed)[:MAX_REPLY]                # unknown shape: hand back the JSON


def sanitize_for_storage(config: dict) -> dict:
    """Strip secrets (api key, auth headers) before a scan is persisted."""
    if not config:
        return {}
    safe = {k: v for k, v in config.items() if k not in ("api_key", "headers")}
    hdrs = config.get("headers") or []
    if hdrs:
        safe["headers"] = [{"name": h.get("name"), "value": "***"} for h in hdrs]
    return safe
