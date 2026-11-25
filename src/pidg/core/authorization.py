from __future__ import annotations

import json
import os
import sqlite3
import time
from pathlib import Path
from typing import Any

from pidg.core.models import canonical, digest


class ApprovalStore:
    """Operator-only DB. Filesystem isolation, not same-UID permissions, supplies trust."""

    def __init__(self, path: Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        fd = os.open(path, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
        os.close(fd)
        self.path = path
        with self.connect() as db:
            db.execute(
                "CREATE TABLE IF NOT EXISTS approvals (action TEXT PRIMARY KEY, expires REAL NOT NULL, granted INTEGER NOT NULL DEFAULT 0, used INTEGER NOT NULL DEFAULT 0, review TEXT NOT NULL DEFAULT '{}')"
            )

    def connect(self) -> sqlite3.Connection:
        return sqlite3.connect(self.path, timeout=2)

    def request(self, action: str, ttl: float = 300, review: dict[str, Any] | None = None) -> None:
        with self.connect() as db:
            db.execute(
                "INSERT OR IGNORE INTO approvals(action,expires,review) VALUES (?,?,?)",
                (action, time.time() + ttl, canonical(review or {})),
            )

    def pending(self) -> list[tuple[str, float]]:
        with self.connect() as db:
            return db.execute(
                "SELECT action,expires FROM approvals WHERE granted=0 AND used=0 AND expires>? ORDER BY action",
                (time.time(),),
            ).fetchall()

    def review(self, action: str) -> dict[str, Any]:
        with self.connect() as db:
            record = db.execute(
                "SELECT review FROM approvals WHERE action=? AND expires>? AND used=0",
                (action, time.time()),
            ).fetchone()
        if not record:
            raise ValueError("unknown or expired action")
        result: dict[str, Any] = json.loads(record[0])
        return result

    def grant(self, action: str, arguments: dict[str, Any] | None = None) -> None:
        review = self.review(action)
        if review and (
            digest(review) != action
            or arguments is None
            or digest(arguments) != review.get("arguments_hash")
        ):
            raise ValueError("exact reviewed arguments required")
        with self.connect() as db:
            count = db.execute(
                "UPDATE approvals SET granted=1 WHERE action=? AND expires>? AND used=0",
                (action, time.time()),
            ).rowcount
            if count != 1:
                raise ValueError("unknown, expired or consumed approval")

    def consume(self, action: str) -> bool:
        with self.connect() as db:
            return (
                db.execute(
                    "UPDATE approvals SET used=1 WHERE action=? AND granted=1 AND used=0 AND expires>?",
                    (action, time.time()),
                ).rowcount
                == 1
            )
