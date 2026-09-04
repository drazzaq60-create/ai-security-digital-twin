# cache.py
# Tiny content-addressed cache for expensive LLM results. Keyed by a hash of the
# INPUT (report text, or findings+focus), so re-running the same report - during a
# demo, a retry, or iterative testing - returns instantly instead of paying the
# (throttled, free-tier) LLM latency again. Stored as JSON under .cache/ (gitignored).

import hashlib
import json
import os

CACHE_DIR = os.path.join(os.path.dirname(__file__), ".cache")


def key_for(*parts):
    raw = "||".join(str(p) for p in parts).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()[:32]


def _path(namespace, key):
    d = os.path.join(CACHE_DIR, namespace)
    os.makedirs(d, exist_ok=True)
    return os.path.join(d, key + ".json")


def get(namespace, key):
    p = _path(namespace, key)
    if os.path.exists(p):
        try:
            with open(p, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            return None
    return None


def set(namespace, key, value):
    try:
        with open(_path(namespace, key), "w", encoding="utf-8") as f:
            json.dump(value, f)
    except Exception:
        pass  # cache is best-effort; never let it break a request
