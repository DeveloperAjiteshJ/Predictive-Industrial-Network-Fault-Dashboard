from __future__ import annotations

import json
import sqlite3
import threading
from pathlib import Path

import pandas as pd

from .config import DB_PATH, MAX_ALERT_HISTORY
from .models import AlertEvent, ChannelSnapshot, Severity


class SQLiteStore:
    def __init__(self, db_path: Path = DB_PATH) -> None:
        self.db_path = Path(db_path)
        self.lock = threading.Lock()
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_db()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL;")
        conn.execute("PRAGMA synchronous=NORMAL;")
        return conn

    def _init_db(self) -> None:
        with self._connect() as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS alert_history (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    channel TEXT NOT NULL,
                    metric_id TEXT NOT NULL,
                    metric_label TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    ts REAL NOT NULL,
                    first_seen REAL NOT NULL,
                    last_seen REAL NOT NULL,
                    duration_seconds REAL NOT NULL,
                    current_value TEXT,
                    baseline_value TEXT,
                    confidence INTEGER NOT NULL,
                    correlation_note TEXT NOT NULL DEFAULT '',
                    occurrence_count INTEGER NOT NULL DEFAULT 0,
                    interpretation TEXT NOT NULL,
                    recommendation TEXT NOT NULL,
                    acknowledged INTEGER NOT NULL DEFAULT 0,
                    resolved INTEGER NOT NULL DEFAULT 0
                )
                """
            )
            alert_columns = {row["name"] for row in conn.execute("PRAGMA table_info(alert_history)").fetchall()}
            if "correlation_note" not in alert_columns:
                conn.execute("ALTER TABLE alert_history ADD COLUMN correlation_note TEXT NOT NULL DEFAULT ''")
            if "occurrence_count" not in alert_columns:
                conn.execute("ALTER TABLE alert_history ADD COLUMN occurrence_count INTEGER NOT NULL DEFAULT 0")
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS metric_counters (
                    channel TEXT NOT NULL,
                    metric_id TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    count INTEGER NOT NULL DEFAULT 0,
                    cumulative_seconds REAL NOT NULL DEFAULT 0,
                    first_seen REAL NOT NULL DEFAULT 0,
                    last_seen REAL NOT NULL DEFAULT 0,
                    PRIMARY KEY(channel, metric_id, severity)
                )
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS baselines (
                    channel TEXT NOT NULL,
                    metric_id TEXT NOT NULL,
                    value TEXT NOT NULL,
                    updated_ts REAL NOT NULL,
                    details TEXT NOT NULL,
                    PRIMARY KEY(channel, metric_id)
                )
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS metric_mutes (
                    channel TEXT NOT NULL,
                    metric_id TEXT NOT NULL,
                    muted INTEGER NOT NULL DEFAULT 0,
                    PRIMARY KEY(channel, metric_id)
                )
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS snapshots (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    channel TEXT NOT NULL,
                    ts REAL NOT NULL,
                    payload TEXT NOT NULL
                )
                """
            )

    def save_alert(self, alert: AlertEvent) -> None:
        with self.lock, self._connect() as conn:
            conn.execute(
                """
                INSERT INTO alert_history (
                    channel, metric_id, metric_label, severity, ts, first_seen, last_seen,
                    duration_seconds, current_value, baseline_value, confidence, correlation_note, occurrence_count,
                    interpretation, recommendation, acknowledged, resolved
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    alert.channel,
                    alert.metric_id,
                    alert.metric_label,
                    alert.severity.value,
                    alert.ts,
                    alert.first_seen,
                    alert.last_seen,
                    alert.duration_seconds,
                    json.dumps(alert.current_value),
                    json.dumps(alert.baseline_value),
                    alert.confidence,
                    alert.correlation_note,
                    alert.occurrence_count,
                    alert.interpretation,
                    alert.recommendation,
                    int(alert.acknowledged),
                    int(alert.resolved),
                ),
            )
            conn.execute("DELETE FROM alert_history WHERE id NOT IN (SELECT id FROM alert_history ORDER BY id DESC LIMIT ?)", (MAX_ALERT_HISTORY,))

    def update_latest_alert(
        self,
        channel: str,
        metric_id: str,
        *,
        acknowledged: bool | None = None,
        resolved: bool | None = None,
        active: bool | None = None,
        duration_seconds: float | None = None,
        last_seen: float | None = None,
        severity: str | None = None,
        current_value: object | None = None,
        baseline_value: object | None = None,
        confidence: int | None = None,
        interpretation: str | None = None,
        recommendation: str | None = None,
        correlation_note: str | None = None,
        occurrence_count: int | None = None,
    ) -> None:
        assignments = []
        params: list[object] = []
        if resolved is None and active is not None:
            resolved = not active
        if acknowledged is not None:
            assignments.append("acknowledged = ?")
            params.append(int(acknowledged))
        if resolved is not None:
            assignments.append("resolved = ?")
            params.append(int(resolved))
        if duration_seconds is not None:
            assignments.append("duration_seconds = ?")
            params.append(duration_seconds)
        if last_seen is not None:
            assignments.append("last_seen = ?")
            params.append(last_seen)
        if severity is not None:
            assignments.append("severity = ?")
            params.append(severity)
        if current_value is not None:
            assignments.append("current_value = ?")
            params.append(json.dumps(current_value))
        if baseline_value is not None:
            assignments.append("baseline_value = ?")
            params.append(json.dumps(baseline_value))
        if confidence is not None:
            assignments.append("confidence = ?")
            params.append(confidence)
        if interpretation is not None:
            assignments.append("interpretation = ?")
            params.append(interpretation)
        if recommendation is not None:
            assignments.append("recommendation = ?")
            params.append(recommendation)
        if correlation_note is not None:
            assignments.append("correlation_note = ?")
            params.append(correlation_note)
        if occurrence_count is not None:
            assignments.append("occurrence_count = ?")
            params.append(occurrence_count)
        if not assignments:
            return
        params.extend([channel, metric_id])
        with self.lock, self._connect() as conn:
            conn.execute(
                f"""
                UPDATE alert_history
                SET {', '.join(assignments)}
                WHERE id = (
                    SELECT id FROM alert_history
                    WHERE channel = ? AND metric_id = ?
                    ORDER BY id DESC
                    LIMIT 1
                )
                """,
                params,
            )

    def update_metric_counter(self, channel: str, metric_id: str, severity: Severity, duration_seconds: float, first_seen: float, last_seen: float) -> None:
        with self.lock, self._connect() as conn:
            conn.execute(
                """
                INSERT INTO metric_counters (channel, metric_id, severity, count, cumulative_seconds, first_seen, last_seen)
                VALUES (?, ?, ?, 1, ?, ?, ?)
                ON CONFLICT(channel, metric_id, severity)
                DO UPDATE SET
                    count = count + 1,
                    cumulative_seconds = cumulative_seconds + excluded.cumulative_seconds,
                    first_seen = CASE WHEN first_seen = 0 OR excluded.first_seen < first_seen THEN excluded.first_seen ELSE first_seen END,
                    last_seen = MAX(last_seen, excluded.last_seen)
                """,
                (channel, metric_id, severity.value, duration_seconds, first_seen, last_seen),
            )

    def save_baseline(self, channel: str, metric_id: str, value: str, details: dict) -> None:
        with self.lock, self._connect() as conn:
            conn.execute(
                """
                INSERT INTO baselines (channel, metric_id, value, updated_ts, details)
                VALUES (?, ?, ?, ?, ?)
                ON CONFLICT(channel, metric_id)
                DO UPDATE SET value = excluded.value, updated_ts = excluded.updated_ts, details = excluded.details
                """,
                (channel, metric_id, value, details.get("ts", 0.0), json.dumps(details)),
            )

    def read_metric_mutes(self, channel: str) -> dict[str, bool]:
        if not self.db_path.exists():
            return {}
        with self._connect() as conn:
            rows = conn.execute("SELECT metric_id, muted FROM metric_mutes WHERE channel = ?", (channel,)).fetchall()
        return {row["metric_id"]: bool(row["muted"]) for row in rows}

    def set_metric_mute(self, channel: str, metric_id: str, muted: bool) -> None:
        with self.lock, self._connect() as conn:
            conn.execute(
                """
                INSERT INTO metric_mutes (channel, metric_id, muted)
                VALUES (?, ?, ?)
                ON CONFLICT(channel, metric_id)
                DO UPDATE SET muted = excluded.muted
                """,
                (channel, metric_id, int(muted)),
            )

    def save_snapshot(self, snapshot: ChannelSnapshot) -> None:
        with self.lock, self._connect() as conn:
            conn.execute(
                "INSERT INTO snapshots (channel, ts, payload) VALUES (?, ?, ?)",
                (snapshot.channel, snapshot.ts, json.dumps(snapshot.to_dict())),
            )

    def clear_channel(self, channel: str) -> None:
        with self.lock, self._connect() as conn:
            conn.execute("DELETE FROM alert_history WHERE channel = ?", (channel,))
            conn.execute("DELETE FROM metric_counters WHERE channel = ?", (channel,))
            conn.execute("DELETE FROM baselines WHERE channel = ?", (channel,))
            conn.execute("DELETE FROM snapshots WHERE channel = ?", (channel,))

    def read_alerts(self, channel: str | None = None, severity: str | None = None, metric_id: str | None = None, limit: int = 500) -> pd.DataFrame:
        if not self.db_path.exists():
            return pd.DataFrame()
        query = "SELECT * FROM alert_history WHERE 1=1"
        params: list[object] = []
        if channel:
            query += " AND channel = ?"
            params.append(channel)
        if severity:
            query += " AND severity = ?"
            params.append(severity)
        if metric_id:
            query += " AND metric_id = ?"
            params.append(metric_id)
        query += " ORDER BY ts DESC, id DESC LIMIT ?"
        params.append(limit)
        with self._connect() as conn:
            return pd.read_sql_query(query, conn, params=params)

    def read_history(self, channel: str, limit: int = 500) -> pd.DataFrame:
        if not self.db_path.exists():
            return pd.DataFrame()
        with self._connect() as conn:
            return pd.read_sql_query(
                "SELECT ts, payload FROM snapshots WHERE channel = ? ORDER BY ts DESC LIMIT ?",
                conn,
                params=(channel, limit),
            )
