"""SQLite audit store. Every decision is kept, with its reasons, for the dashboard and audits."""

from __future__ import annotations

import sqlite3
import threading
from collections.abc import Sequence
from datetime import datetime, timezone
from decimal import Decimal

from .models import Decision, Mandate

_SCHEMA = """
CREATE TABLE IF NOT EXISTS mandates (
    id TEXT PRIMARY KEY,
    created_at TEXT NOT NULL,
    data TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS decisions (
    id TEXT PRIMARY KEY,
    mandate_id TEXT NOT NULL,
    created_at TEXT NOT NULL,
    outcome TEXT NOT NULL,
    status TEXT NOT NULL,
    total TEXT NOT NULL,
    paypal_order_id TEXT,
    data TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_decisions_mandate ON decisions (mandate_id, created_at);
CREATE INDEX IF NOT EXISTS idx_decisions_order ON decisions (paypal_order_id);
CREATE TABLE IF NOT EXISTS used_quotes (
    qid TEXT PRIMARY KEY,
    decision_id TEXT NOT NULL,
    used_at TEXT NOT NULL
);
"""


class Store:
    def __init__(self, path: str = ":memory:") -> None:
        self._conn = sqlite3.connect(path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._lock = threading.RLock()
        with self._lock:
            self._conn.executescript(_SCHEMA)
            self._conn.commit()

    # --- mandates -----------------------------------------------------------------
    def save_mandate(self, mandate: Mandate) -> None:
        with self._lock:
            self._conn.execute(
                "INSERT INTO mandates (id, created_at, data) VALUES (?, ?, ?) "
                "ON CONFLICT(id) DO UPDATE SET data = excluded.data",
                (mandate.id, mandate.created_at.isoformat(), mandate.model_dump_json()),
            )
            self._conn.commit()

    def get_mandate(self, mandate_id: str) -> Mandate | None:
        with self._lock:
            row = self._conn.execute("SELECT data FROM mandates WHERE id = ?", (mandate_id,)).fetchone()
        return Mandate.model_validate_json(row["data"]) if row else None

    def list_mandates(self) -> list[Mandate]:
        with self._lock:
            rows = self._conn.execute("SELECT data FROM mandates ORDER BY created_at DESC").fetchall()
        return [Mandate.model_validate_json(r["data"]) for r in rows]

    # --- decisions ----------------------------------------------------------------
    def save_decision(self, decision: Decision) -> None:
        with self._lock:
            self._conn.execute(
                "INSERT INTO decisions (id, mandate_id, created_at, outcome, status, total, paypal_order_id, data) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?) "
                "ON CONFLICT(id) DO UPDATE SET outcome = excluded.outcome, status = excluded.status, "
                "total = excluded.total, paypal_order_id = excluded.paypal_order_id, data = excluded.data",
                (
                    decision.id,
                    decision.mandate_id,
                    decision.created_at.isoformat(),
                    decision.outcome.value,
                    decision.status,
                    str(decision.total),
                    decision.paypal_order_id,
                    decision.model_dump_json(),
                ),
            )
            self._conn.commit()

    def get_decision(self, decision_id: str) -> Decision | None:
        with self._lock:
            row = self._conn.execute("SELECT data FROM decisions WHERE id = ?", (decision_id,)).fetchone()
        return Decision.model_validate_json(row["data"]) if row else None

    def find_by_order(self, order_id: str) -> Decision | None:
        with self._lock:
            row = self._conn.execute(
                "SELECT data FROM decisions WHERE paypal_order_id = ?", (order_id,)
            ).fetchone()
        return Decision.model_validate_json(row["data"]) if row else None

    def list_decisions(self, limit: int = 200) -> list[Decision]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT data FROM decisions ORDER BY created_at DESC LIMIT ?", (limit,)
            ).fetchall()
        return [Decision.model_validate_json(r["data"]) for r in rows]

    def spent_since(self, mandate_id: str, since: datetime, statuses: Sequence[str]) -> Decimal:
        marks = ",".join("?" for _ in statuses)
        with self._lock:
            rows = self._conn.execute(
                f"SELECT total FROM decisions WHERE mandate_id = ? AND created_at >= ? AND status IN ({marks})",
                (mandate_id, since.isoformat(), *statuses),
            ).fetchall()
        return sum((Decimal(r["total"]) for r in rows), Decimal("0.00"))

    def recent_times(self, mandate_id: str, since: datetime, statuses: Sequence[str]) -> list[datetime]:
        marks = ",".join("?" for _ in statuses)
        with self._lock:
            rows = self._conn.execute(
                f"SELECT created_at FROM decisions WHERE mandate_id = ? AND created_at >= ? AND status IN ({marks})",
                (mandate_id, since.isoformat(), *statuses),
            ).fetchall()
        return [datetime.fromisoformat(r["created_at"]) for r in rows]

    # --- quotes -------------------------------------------------------------------
    def claim_quote(self, qid: str, decision_id: str) -> bool:
        """Mark a quote as used. Returns False if it was already used (replay)."""
        with self._lock:
            try:
                self._conn.execute(
                    "INSERT INTO used_quotes (qid, decision_id, used_at) VALUES (?, ?, ?)",
                    (qid, decision_id, datetime.now(timezone.utc).isoformat()),
                )
                self._conn.commit()
                return True
            except sqlite3.IntegrityError:
                return False
