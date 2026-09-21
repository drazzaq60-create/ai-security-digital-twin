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


class SqlScanStore(ScanStore):
    """Relational backend (Supabase Postgres in prod, SQLite for tests). Keeps the full
    record in a JSON column so get()/list() return the identical dicts the disk store did,
    and mirrors each finding into a `findings` table for dashboard-style SQL aggregation."""

    def __init__(self, url: str):
        from sqlalchemy.orm import sessionmaker
        from db import Base, Scan, Finding, make_engine
        self._Scan, self._Finding = Scan, Finding
        self.engine = make_engine(url)
        Base.metadata.create_all(self.engine)
        self.Session = sessionmaker(bind=self.engine, future=True)

    def _findings_of(self, record: dict) -> list:
        rows = []
        for r in record.get("reports") or []:
            for f in r.get("findings") or []:
                rows.append(self._Finding(
                    name=f.get("name"), host=f.get("host"),
                    severity=f.get("severity"), ftype=f.get("type"),
                    source=f.get("source"), evidence=(f.get("evidence") or "")[:2000],
                ))
        return rows

    def save(self, record: dict) -> str:
        sid = record.get("_id") or new_id()
        record["_id"] = sid
        meta = record.get("meta") or {}
        with self.Session.begin() as s:
            obj = s.get(self._Scan, sid)
            if obj is None:
                obj = self._Scan(id=sid)
                s.add(obj)
            obj.module = record.get("module", "upload")
            obj.target = record.get("target", "")
            obj.score = record.get("score", meta.get("score"))
            obj.band = meta.get("band")
            obj.label = record.get("label")
            obj.tag = record.get("tag")
            obj.created = record.get("_created")
            obj.data = record
            obj.findings = self._findings_of(record)  # replaces (delete-orphan)
        return sid

    def list(self, limit: int = 100) -> list:
        with self.Session() as s:
            rows = s.query(self._Scan).order_by(self._Scan.created.desc()).limit(limit).all()
            return [r.data for r in rows]

    def get(self, scan_id: str) -> Optional[dict]:
        with self.Session() as s:
            obj = s.get(self._Scan, scan_id)
            return obj.data if obj else None

    def update(self, scan_id: str, fields: dict) -> bool:
        with self.Session.begin() as s:
            obj = s.get(self._Scan, scan_id)
            if obj is None:
                return False
            data = dict(obj.data or {})
            data.update(fields)
            obj.data = data
            if "label" in fields:
                obj.label = fields["label"]
            if "tag" in fields:
                obj.tag = fields["tag"]
            return True

    def delete(self, scan_id: str) -> bool:
        with self.Session.begin() as s:
            obj = s.get(self._Scan, scan_id)
            if obj is not None:
                s.delete(obj)
        return True


_store: Optional[ScanStore] = None


def get_store() -> ScanStore:
    """The single persistence entry point the API uses. Uses Postgres/SQLite when a DB URL
    is configured (DATABASE_URL or SUPABASE_DB_URL), otherwise falls back to disk. This is
    the seam: adding the env var switches the whole platform to a real DB, no code changes."""
    global _store
    if _store is None:
        url = os.getenv("DATABASE_URL") or os.getenv("SUPABASE_DB_URL")
        if url:
            try:
                _store = SqlScanStore(url)
                print("[store] using SQL store")
            except Exception as e:
                print(f"[store] SQL store init failed ({e}); falling back to disk")
                _store = DiskScanStore(os.path.join(os.path.dirname(__file__), "runs"))
        else:
            _store = DiskScanStore(os.path.join(os.path.dirname(__file__), "runs"))
    return _store
