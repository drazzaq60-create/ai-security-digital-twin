# store.py
# Swappable persistence for saved scans. Disk-backed today; in Phase 4 a PostgresScanStore
# can implement the SAME ScanStore interface (Supabase) and the API code won't change - it
# only ever talks to get_store(). This is the seam that keeps the DB migration low-risk.

import json
import os
import time
import uuid
from abc import ABC, abstractmethod
from typing import Optional


def new_id() -> str:
    """Sortable, unique scan id: 20260921-143512-a1b2c3."""
    return time.strftime("%Y%m%d-%H%M%S") + "-" + uuid.uuid4().hex[:6]


class ScanStore(ABC):
    """One saved scan = a JSON-serialisable dict (reports, correlation, graph, module,
    target, score, meta, ...). Backends just persist and return these dicts."""

    @abstractmethod
    def save(self, record: dict) -> str: ...

    @abstractmethod
    def list(self, limit: int = 100) -> list: ...

    @abstractmethod
    def get(self, scan_id: str) -> Optional[dict]: ...

    @abstractmethod
    def update(self, scan_id: str, fields: dict) -> bool: ...

    @abstractmethod
    def delete(self, scan_id: str) -> bool: ...


class DiskScanStore(ScanStore):
    """Stores each scan as <dir>/<id>.json. Backward-compatible with the old runs/ files."""

    def __init__(self, path: str):
        self.path = path
        os.makedirs(path, exist_ok=True)

    def _p(self, scan_id: str) -> str:
        return os.path.join(self.path, os.path.basename(scan_id) + ".json")  # basename = no traversal

    def save(self, record: dict) -> str:
        sid = record.get("_id") or new_id()
        record["_id"] = sid
        with open(self._p(sid), "w", encoding="utf-8") as f:
            json.dump(record, f)
        return sid

    def list(self, limit: int = 100) -> list:
        out = []
        for fn in sorted(os.listdir(self.path), reverse=True):
            if not fn.endswith(".json"):
                continue
            try:
                with open(os.path.join(self.path, fn), encoding="utf-8") as f:
                    out.append(json.load(f))
            except Exception:
                continue
        return out[:limit]

    def get(self, scan_id: str) -> Optional[dict]:
        p = self._p(scan_id)
        if not os.path.exists(p):
            return None
        with open(p, encoding="utf-8") as f:
            return json.load(f)

    def update(self, scan_id: str, fields: dict) -> bool:
        d = self.get(scan_id)
        if d is None:
            return False
        d.update(fields)
        with open(self._p(scan_id), "w", encoding="utf-8") as f:
            json.dump(d, f)
        return True

    def delete(self, scan_id: str) -> bool:
        p = self._p(scan_id)
        if os.path.exists(p):
            os.remove(p)
        return True


_store: Optional[ScanStore] = None


def get_store() -> ScanStore:
    """The single persistence entry point the API uses. Swap the backend here in Phase 4."""
    global _store
    if _store is None:
        _store = DiskScanStore(os.path.join(os.path.dirname(__file__), "runs"))
    return _store
