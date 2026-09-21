# jobs.py
# A tiny in-memory job registry for long-running scans (the AI red-team fires many LLM
# calls and can take minutes - far longer than one HTTP request should block). A scan is
# started as a background thread; the client polls a job id for status + live log.
#
# In-memory is fine for a single-instance demo. If we ever run multiple backend workers,
# this moves to Redis/DB - but that's roadmap, not now.

import threading
import time
import uuid

_jobs: dict = {}
_lock = threading.Lock()


def create(kind: str, target: str) -> str:
    jid = uuid.uuid4().hex[:12]
    with _lock:
        _jobs[jid] = {
            "id": jid, "kind": kind, "target": target,
            "status": "running",           # running | done | error
            "log": [], "progress": {"attempts": 0, "budget": 0},
            "result": None, "error": None, "created": time.time(),
        }
    return jid


def get(jid: str):
    with _lock:
        j = _jobs.get(jid)
        return dict(j) if j else None


def set_log(jid: str, log: list):
    with _lock:
        if jid in _jobs:
            _jobs[jid]["log"] = list(log)


def set_progress(jid: str, **kw):
    with _lock:
        if jid in _jobs:
            _jobs[jid]["progress"].update(kw)


def finish(jid: str, result: dict):
    with _lock:
        if jid in _jobs:
            _jobs[jid]["status"] = "done"
            _jobs[jid]["result"] = result


def fail(jid: str, error: str):
    with _lock:
        if jid in _jobs:
            _jobs[jid]["status"] = "error"
            _jobs[jid]["error"] = error


def run_in_thread(fn, *args):
    t = threading.Thread(target=fn, args=args, daemon=True)
    t.start()
    return t
