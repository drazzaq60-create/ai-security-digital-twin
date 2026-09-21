# db.py
# SQLAlchemy models for the Sentinel platform's relational store (Supabase Postgres in
# production; SQLite works for local dev/tests). Two tables:
#   scans    - one row per saved scan; typed columns for querying + a JSON `data` column
#              that holds the FULL record so get()/list() return the exact same shape the
#              disk store did (no lossy migration).
#   findings - one row per finding, so the dashboard can aggregate severity/module across
#              scans with plain SQL (this is the relational-design signal, and what the
#              spec's schema asked for).
#
# Portable on purpose: JSON column + generic types work on both Postgres and SQLite.

from sqlalchemy import (
    Column, String, Integer, Float, Text, JSON, ForeignKey, create_engine,
)
from sqlalchemy.orm import declarative_base, relationship

Base = declarative_base()


class Scan(Base):
    __tablename__ = "scans"
    id = Column(String, primary_key=True)
    module = Column(String, index=True)          # ai | web | upload
    target = Column(Text)
    score = Column(Integer)
    band = Column(String)
    label = Column(String)
    tag = Column(String)
    created = Column(Float, index=True)
    data = Column(JSON)                            # full record (fidelity)
    # ORM-level cascade (works on SQLite + Postgres); the FK ondelete="CASCADE" adds
    # DB-level integrity on Postgres. Not passive, so deletes are correct even on SQLite.
    findings = relationship(
        "Finding", back_populates="scan", cascade="all, delete-orphan",
    )


class Finding(Base):
    __tablename__ = "findings"
    id = Column(Integer, primary_key=True, autoincrement=True)
    scan_id = Column(String, ForeignKey("scans.id", ondelete="CASCADE"), index=True)
    name = Column(Text)
    host = Column(Text)
    severity = Column(String, index=True)
    ftype = Column("type", String)
    source = Column(String)
    evidence = Column(Text)
    scan = relationship("Scan", back_populates="findings")


def normalize_url(url: str) -> str:
    """Accept a bare Supabase/Postgres URI and make it an explicit SQLAlchemy driver URL."""
    if url.startswith("postgres://"):        # some providers hand out this scheme
        url = "postgresql+psycopg2://" + url[len("postgres://"):]
    elif url.startswith("postgresql://"):
        url = "postgresql+psycopg2://" + url[len("postgresql://"):]
    return url


def make_engine(url: str):
    """Create an engine. pool_pre_ping avoids stale-connection errors on free tiers that
    drop idle connections. Postgres (Supabase) requires SSL, so force it unless the URL
    already specifies sslmode."""
    norm = normalize_url(url)
    connect_args = {}
    if norm.startswith("postgresql") and "sslmode" not in norm:
        connect_args["sslmode"] = "require"
    return create_engine(norm, pool_pre_ping=True, future=True, connect_args=connect_args)
