"""Minimal local audit store. Raw message content is intentionally never persisted."""

from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


DATABASE_PATH = Path(__file__).resolve().parent / "phishlens_history.db"


def connection() -> sqlite3.Connection:
    database = sqlite3.connect(DATABASE_PATH)
    database.row_factory = sqlite3.Row
    return database


def initialize_database() -> None:
    with connection() as database:
        database.execute("""
            CREATE TABLE IF NOT EXISTS analyses (
                id TEXT PRIMARY KEY,
                created_at TEXT NOT NULL,
                content_hash TEXT NOT NULL,
                risk_score REAL NOT NULL,
                severity TEXT NOT NULL,
                model_probability REAL NOT NULL,
                signal_count INTEGER NOT NULL,
                signals_json TEXT NOT NULL,
                feedback TEXT
            )
        """)


def save_analysis(record: dict[str, Any]) -> None:
    with connection() as database:
        database.execute(
            """INSERT INTO analyses
               (id, created_at, content_hash, risk_score, severity, model_probability, signal_count, signals_json)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                record["id"],
                datetime.now(timezone.utc).isoformat(),
                record["content_hash"],
                record["risk_score"],
                record["severity"],
                record["model_probability"],
                len(record["signals"]),
                json.dumps(record["signals"]),
            ),
        )


def recent_analyses(limit: int) -> list[dict[str, Any]]:
    with connection() as database:
        rows = database.execute(
            """SELECT id, created_at, risk_score, severity, model_probability, signal_count, signals_json, feedback
               FROM analyses ORDER BY created_at DESC LIMIT ?""", (limit,)
        ).fetchall()
    return [
        {
            **dict(row),
            "signals": json.loads(row["signals_json"]),
            "signals_json": None,
        }
        for row in rows
    ]


def save_feedback(analysis_id: str, outcome: str) -> bool:
    with connection() as database:
        cursor = database.execute("UPDATE analyses SET feedback = ? WHERE id = ?", (outcome, analysis_id))
    return cursor.rowcount == 1
