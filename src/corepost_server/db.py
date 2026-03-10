from __future__ import annotations

import sqlite3
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator


class Database:
    def __init__(self, path: Path):
        self.path = path

    @contextmanager
    def connect(self) -> Iterator[sqlite3.Connection]:
        conn = sqlite3.connect(self.path, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON")
        try:
            yield conn
        finally:
            conn.close()

    def init(self) -> None:
        with self.connect() as conn:
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS devices (
                    device_id TEXT PRIMARY KEY,
                    emergency_id TEXT NOT NULL UNIQUE,
                    display_name TEXT,
                    hwid TEXT,
                    unlock_profile TEXT NOT NULL,
                    usb_key_id TEXT,
                    device_secret TEXT NOT NULL,
                    panic_secret TEXT NOT NULL,
                    unlock_token TEXT NOT NULL,
                    current_state TEXT NOT NULL,
                    user_can_unlock INTEGER NOT NULL DEFAULT 1,
                    agent_action TEXT NOT NULL DEFAULT 'observe',
                    pending_lock_at TEXT,
                    last_seen TEXT,
                    last_preboot_at TEXT,
                    last_mobile_action_at TEXT,
                    last_agent_action_at TEXT,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    device_id TEXT NOT NULL,
                    event_type TEXT NOT NULL,
                    actor TEXT NOT NULL,
                    previous_state TEXT,
                    next_state TEXT,
                    details_json TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    FOREIGN KEY (device_id) REFERENCES devices(device_id) ON DELETE CASCADE
                );

                CREATE INDEX IF NOT EXISTS idx_events_device_created
                ON events(device_id, created_at DESC);
                """
            )
            conn.commit()
