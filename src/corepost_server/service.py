from __future__ import annotations

import json
import secrets
import sqlite3
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Optional

from fastapi import HTTPException, status

from corepost_server.config import Settings
from corepost_server.db import Database
from corepost_server.schemas import AgentAction


ALLOWED_DECRYPT_STATES = {"registered", "normal", "recovered"}
BLOCKED_CLIENT_STATES = {"pending_lock", "locked", "restricted"}


def utc_now() -> datetime:
    return datetime.now(tz=timezone.utc)


def utc_now_iso() -> str:
    return utc_now().isoformat()


@dataclass
class AuthenticatedDevice:
    row: sqlite3.Row

    @property
    def device_id(self) -> str:
        return self.row["device_id"]


class CorePostService:
    def __init__(self, settings: Settings):
        self.settings = settings
        self.db = Database(settings.db_path)
        self.db.init()

    def _row_to_device(self, row: sqlite3.Row) -> dict[str, Any]:
        return {
            "deviceId": row["device_id"],
            "emergencyId": row["emergency_id"],
            "currentState": row["current_state"],
            "displayName": row["display_name"],
            "hwid": row["hwid"],
            "unlockProfile": row["unlock_profile"],
            "usbKeyId": row["usb_key_id"],
            "userCanUnlock": bool(row["user_can_unlock"]),
            "agentAction": row["agent_action"],
            "lastSeen": row["last_seen"],
            "createdAt": row["created_at"],
            "updatedAt": row["updated_at"],
        }

    def _row_to_bundle(self, row: sqlite3.Row) -> dict[str, Any]:
        return {
            "deviceId": row["device_id"],
            "emergencyId": row["emergency_id"],
            "deviceSecret": row["device_secret"],
            "panicSecret": row["panic_secret"],
            "unlockToken": row["unlock_token"],
            "currentState": row["current_state"],
            "unlockProfile": row["unlock_profile"],
            "userCanUnlock": bool(row["user_can_unlock"]),
        }

    def _fetch_device(self, conn: sqlite3.Connection, *, device_id: Optional[str] = None, emergency_id: Optional[str] = None) -> sqlite3.Row | None:
        if device_id:
            return conn.execute("SELECT * FROM devices WHERE device_id = ?", (device_id,)).fetchone()
        if emergency_id:
            return conn.execute("SELECT * FROM devices WHERE emergency_id = ?", (emergency_id,)).fetchone()
        raise ValueError("device_id or emergency_id is required")

    def _log_event(
        self,
        conn: sqlite3.Connection,
        *,
        device_id: str,
        event_type: str,
        actor: str,
        previous_state: Optional[str],
        next_state: Optional[str],
        details: Optional[dict[str, Any]] = None,
    ) -> None:
        conn.execute(
            """
            INSERT INTO events (device_id, event_type, actor, previous_state, next_state, details_json, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                device_id,
                event_type,
                actor,
                previous_state,
                next_state,
                json.dumps(details or {}, sort_keys=True),
                utc_now_iso(),
            ),
        )

    def _new_identifier(self) -> str:
        return secrets.token_hex(8)

    def _new_secret(self) -> str:
        return secrets.token_hex(32)

    def _validate_hwid(self, row: sqlite3.Row, hwid: Optional[str]) -> None:
        if self.settings.require_hwid and not hwid:
            raise HTTPException(status_code=400, detail="HWID is required")
        if row["hwid"] and hwid and row["hwid"] != hwid:
            raise HTTPException(status_code=409, detail="HWID mismatch")

    def register_client(self, payload: dict[str, Any]) -> dict[str, Any]:
        now = utc_now_iso()
        with self.db.connect() as conn:
            if self.settings.require_registration_approval:
                if not payload.get("deviceId"):
                    raise HTTPException(status_code=400, detail="deviceId is required when registration approval is enabled")
                row = self._fetch_device(conn, device_id=payload["deviceId"])
                if row is None:
                    raise HTTPException(status_code=404, detail="Device is not pre-registered")
                self._validate_hwid(row, payload.get("hwid"))
                conn.execute(
                    """
                    UPDATE devices
                    SET display_name = COALESCE(?, display_name),
                        hwid = COALESCE(?, hwid),
                        updated_at = ?
                    WHERE device_id = ?
                    """,
                    (payload.get("displayName"), payload.get("hwid"), now, payload["deviceId"]),
                )
                row = self._fetch_device(conn, device_id=payload["deviceId"])
                self._log_event(
                    conn,
                    device_id=row["device_id"],
                    event_type="client_registration_confirmed",
                    actor="client",
                    previous_state=row["current_state"],
                    next_state=row["current_state"],
                    details={"hwid": payload.get("hwid")},
                )
                conn.commit()
                return self._row_to_bundle(row)

            device_id = payload.get("deviceId") or self._new_identifier()
            while self._fetch_device(conn, device_id=device_id) is not None:
                device_id = self._new_identifier()

            if self.settings.require_hwid and not payload.get("hwid"):
                raise HTTPException(status_code=400, detail="HWID is required")

            conn.execute(
                """
                INSERT INTO devices (
                    device_id, emergency_id, display_name, hwid, unlock_profile, usb_key_id,
                    device_secret, panic_secret, unlock_token, current_state, user_can_unlock,
                    agent_action, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    device_id,
                    self._new_identifier(),
                    payload.get("displayName"),
                    payload.get("hwid"),
                    payload["unlockProfile"],
                    payload.get("usbKeyId"),
                    self._new_secret(),
                    self._new_secret(),
                    self._new_secret(),
                    "registered",
                    1,
                    "observe",
                    now,
                    now,
                ),
            )
            row = self._fetch_device(conn, device_id=device_id)
            self._log_event(
                conn,
                device_id=device_id,
                event_type="client_registered",
                actor="client",
                previous_state=None,
                next_state="registered",
                details={"unlockProfile": payload["unlockProfile"]},
            )
            conn.commit()
            return self._row_to_bundle(row)

    def register_admin(self, payload: dict[str, Any]) -> dict[str, Any]:
        now = utc_now_iso()
        with self.db.connect() as conn:
            device_id = payload.get("deviceId") or self._new_identifier()
            while self._fetch_device(conn, device_id=device_id) is not None:
                device_id = self._new_identifier()
            conn.execute(
                """
                INSERT INTO devices (
                    device_id, emergency_id, display_name, hwid, unlock_profile, usb_key_id,
                    device_secret, panic_secret, unlock_token, current_state, user_can_unlock,
                    agent_action, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    device_id,
                    self._new_identifier(),
                    payload.get("displayName"),
                    payload.get("hwid"),
                    payload["unlockProfile"],
                    payload.get("usbKeyId"),
                    self._new_secret(),
                    self._new_secret(),
                    self._new_secret(),
                    "registered",
                    1 if payload.get("userCanUnlock", True) else 0,
                    payload.get("agentAction", "observe"),
                    now,
                    now,
                ),
            )
            row = self._fetch_device(conn, device_id=device_id)
            self._log_event(
                conn,
                device_id=device_id,
                event_type="admin_registered",
                actor="admin",
                previous_state=None,
                next_state="registered",
                details={"unlockProfile": payload["unlockProfile"]},
            )
            conn.commit()
            return self._row_to_bundle(row)

    def authenticate_device(self, device_id: str) -> sqlite3.Row:
        with self.db.connect() as conn:
            row = self._fetch_device(conn, device_id=device_id)
            if row is None:
                raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Device not found")
            return row

    def authenticate_emergency(self, emergency_id: str) -> sqlite3.Row:
        with self.db.connect() as conn:
            row = self._fetch_device(conn, emergency_id=emergency_id)
            if row is None:
                raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Device not found")
            return row

    def client_status(self, device_id: str) -> dict[str, Any]:
        now = utc_now_iso()
        with self.db.connect() as conn:
            row = self._fetch_device(conn, device_id=device_id)
            previous_state = row["current_state"]
            next_state = "normal" if previous_state in {"registered", "recovered"} else previous_state
            if next_state != previous_state:
                conn.execute(
                    "UPDATE devices SET current_state = ?, updated_at = ? WHERE device_id = ?",
                    (next_state, now, device_id),
                )
            conn.execute(
                "UPDATE devices SET last_seen = ?, updated_at = ? WHERE device_id = ?",
                (now, now, device_id),
            )
            if next_state in BLOCKED_CLIENT_STATES:
                self._log_event(
                    conn,
                    device_id=device_id,
                    event_type="client_heartbeat_denied",
                    actor="preboot",
                    previous_state=previous_state,
                    next_state=next_state,
                    details={},
                )
                conn.commit()
                raise HTTPException(status_code=403, detail=f"Device is {next_state}")
            if next_state != previous_state:
                self._log_event(
                    conn,
                    device_id=device_id,
                    event_type="device_state_advanced",
                    actor="preboot",
                    previous_state=previous_state,
                    next_state=next_state,
                    details={},
                )
            conn.commit()
            row = self._fetch_device(conn, device_id=device_id)
            return {
                "deviceId": device_id,
                "currentState": row["current_state"],
                "unlockProfile": row["unlock_profile"],
                "userCanUnlock": bool(row["user_can_unlock"]),
                "heartbeatIntervalSecond": self.settings.heartbeat_interval_seconds,
            }

    def client_decrypt(self, device_id: str) -> str:
        now = utc_now_iso()
        with self.db.connect() as conn:
            row = self._fetch_device(conn, device_id=device_id)
            previous_state = row["current_state"]
            if previous_state in BLOCKED_CLIENT_STATES:
                self._log_event(
                    conn,
                    device_id=device_id,
                    event_type="decrypt_denied",
                    actor="preboot",
                    previous_state=previous_state,
                    next_state=previous_state,
                    details={},
                )
                conn.commit()
                raise HTTPException(status_code=403, detail=f"Device is {previous_state}")
            next_state = "normal" if previous_state in {"registered", "recovered"} else previous_state
            conn.execute(
                """
                UPDATE devices
                SET current_state = ?, last_seen = ?, last_preboot_at = ?, updated_at = ?
                WHERE device_id = ?
                """,
                (next_state, now, now, now, device_id),
            )
            self._log_event(
                conn,
                device_id=device_id,
                event_type="decrypt_granted",
                actor="preboot",
                previous_state=previous_state,
                next_state=next_state,
                details={"unlockProfile": row["unlock_profile"]},
            )
            conn.commit()
            return row["unlock_token"]

    def mobile_check(self, emergency_id: str) -> dict[str, Any]:
        with self.db.connect() as conn:
            row = self._fetch_device(conn, emergency_id=emergency_id)
            return {
                "deviceId": row["device_id"],
                "currentState": row["current_state"],
                "userCanUnlock": bool(row["user_can_unlock"]),
                "needLockApproval": self.settings.require_lock_confirmation,
                "lockApprovalTimeSecond": self.settings.lock_confirmation_window_seconds,
            }

    def mobile_lock(self, emergency_id: str) -> tuple[int, dict[str, Any]]:
        now_dt = utc_now()
        now = now_dt.isoformat()
        with self.db.connect() as conn:
            row = self._fetch_device(conn, emergency_id=emergency_id)
            current_state = row["current_state"]
            if current_state == "locked":
                return 200, {"detail": "Device already locked"}

            if self.settings.require_lock_confirmation:
                if current_state != "pending_lock" or not row["pending_lock_at"]:
                    conn.execute(
                        "UPDATE devices SET current_state = ?, pending_lock_at = ?, last_mobile_action_at = ?, updated_at = ? WHERE emergency_id = ?",
                        ("pending_lock", now, now, now, emergency_id),
                    )
                    self._log_event(
                        conn,
                        device_id=row["device_id"],
                        event_type="panic_lock_pending",
                        actor="mobile",
                        previous_state=current_state,
                        next_state="pending_lock",
                        details={},
                    )
                    conn.commit()
                    return 201, {"detail": "Lock confirmation required", "currentState": "pending_lock"}

                pending_at = datetime.fromisoformat(row["pending_lock_at"])
                if now_dt - pending_at > timedelta(seconds=self.settings.lock_confirmation_window_seconds):
                    conn.execute(
                        "UPDATE devices SET pending_lock_at = ?, last_mobile_action_at = ?, updated_at = ? WHERE emergency_id = ?",
                        (now, now, now, emergency_id),
                    )
                    conn.commit()
                    return 201, {"detail": "Lock confirmation window restarted", "currentState": "pending_lock"}

            conn.execute(
                "UPDATE devices SET current_state = ?, pending_lock_at = NULL, last_mobile_action_at = ?, updated_at = ? WHERE emergency_id = ?",
                ("locked", now, now, emergency_id),
            )
            self._log_event(
                conn,
                device_id=row["device_id"],
                event_type="panic_lock_confirmed",
                actor="mobile",
                previous_state=current_state,
                next_state="locked",
                details={},
            )
            conn.commit()
            return 200, {"detail": "Device locked", "currentState": "locked"}

    def mobile_unlock(self, emergency_id: str) -> dict[str, Any]:
        now = utc_now_iso()
        with self.db.connect() as conn:
            row = self._fetch_device(conn, emergency_id=emergency_id)
            if not bool(row["user_can_unlock"]):
                raise HTTPException(status_code=403, detail="User unlock is disabled")
            previous_state = row["current_state"]
            next_state = "recovered"
            conn.execute(
                """
                UPDATE devices
                SET current_state = ?, pending_lock_at = NULL, last_mobile_action_at = ?, updated_at = ?
                WHERE emergency_id = ?
                """,
                (next_state, now, now, emergency_id),
            )
            self._log_event(
                conn,
                device_id=row["device_id"],
                event_type="mobile_unlock",
                actor="mobile",
                previous_state=previous_state,
                next_state=next_state,
                details={},
            )
            conn.commit()
            return {"detail": "Device moved to recovered", "currentState": next_state}

    def agent_poll(self, device_id: str) -> dict[str, Any]:
        now = utc_now_iso()
        with self.db.connect() as conn:
            row = self._fetch_device(conn, device_id=device_id)
            previous_state = row["current_state"]
            next_state = "normal" if previous_state == "registered" else previous_state
            if next_state != previous_state:
                conn.execute(
                    "UPDATE devices SET current_state = ?, updated_at = ? WHERE device_id = ?",
                    (next_state, now, device_id),
                )
            conn.execute(
                "UPDATE devices SET last_seen = ?, last_agent_action_at = ?, updated_at = ? WHERE device_id = ?",
                (now, now, now, device_id),
            )
            if next_state != previous_state:
                self._log_event(
                    conn,
                    device_id=device_id,
                    event_type="agent_state_advanced",
                    actor="agent",
                    previous_state=previous_state,
                    next_state=next_state,
                    details={},
                )
            conn.commit()
            row = self._fetch_device(conn, device_id=device_id)
            action: AgentAction
            if row["current_state"] == "locked":
                action = self.settings.agent_action_when_locked  # type: ignore[assignment]
            elif row["current_state"] == "restricted":
                action = self.settings.agent_action_when_restricted  # type: ignore[assignment]
            else:
                action = row["agent_action"]  # type: ignore[assignment]
            return {
                "deviceId": row["device_id"],
                "currentState": row["current_state"],
                "action": action,
                "unlockProfile": row["unlock_profile"],
                "userCanUnlock": bool(row["user_can_unlock"]),
                "heartbeatIntervalSecond": self.settings.heartbeat_interval_seconds,
            }

    def agent_ack(self, device_id: str, payload: dict[str, Any]) -> dict[str, Any]:
        with self.db.connect() as conn:
            row = self._fetch_device(conn, device_id=device_id)
            self._log_event(
                conn,
                device_id=device_id,
                event_type="agent_ack",
                actor="agent",
                previous_state=row["current_state"],
                next_state=row["current_state"],
                details=payload,
            )
            conn.commit()
            return {"detail": "Agent acknowledgement recorded"}

    def admin_unlock(self, payload: dict[str, Any]) -> dict[str, Any]:
        now = utc_now_iso()
        with self.db.connect() as conn:
            row = self._fetch_device(conn, device_id=payload.get("deviceId"), emergency_id=payload.get("emergencyId"))
            if row is None:
                raise HTTPException(status_code=404, detail="Device not found")
            previous_state = row["current_state"]
            next_state = payload["targetState"]
            conn.execute(
                """
                UPDATE devices
                SET current_state = ?, pending_lock_at = NULL, updated_at = ?
                WHERE device_id = ?
                """,
                (next_state, now, row["device_id"]),
            )
            self._log_event(
                conn,
                device_id=row["device_id"],
                event_type="admin_unlock",
                actor="admin",
                previous_state=previous_state,
                next_state=next_state,
                details={},
            )
            conn.commit()
            return {"detail": "Device state updated", "currentState": next_state}

    def get_device(self, device_id: str) -> dict[str, Any]:
        with self.db.connect() as conn:
            row = self._fetch_device(conn, device_id=device_id)
            if row is None:
                raise HTTPException(status_code=404, detail="Device not found")
            return self._row_to_device(row)

    def list_devices(self) -> list[dict[str, Any]]:
        with self.db.connect() as conn:
            rows = conn.execute("SELECT * FROM devices ORDER BY created_at ASC").fetchall()
            return [self._row_to_device(row) for row in rows]

    def patch_device(self, device_id: str, payload: dict[str, Any]) -> dict[str, Any]:
        now = utc_now_iso()
        with self.db.connect() as conn:
            row = self._fetch_device(conn, device_id=device_id)
            if row is None:
                raise HTTPException(status_code=404, detail="Device not found")
            next_state = payload.get("currentState", row["current_state"])
            user_can_unlock = row["user_can_unlock"] if payload.get("userCanUnlock") is None else int(bool(payload["userCanUnlock"]))
            agent_action = payload.get("agentAction", row["agent_action"])
            conn.execute(
                """
                UPDATE devices
                SET current_state = ?, user_can_unlock = ?, agent_action = ?, updated_at = ?
                WHERE device_id = ?
                """,
                (next_state, user_can_unlock, agent_action, now, device_id),
            )
            self._log_event(
                conn,
                device_id=device_id,
                event_type="admin_patch_device",
                actor="admin",
                previous_state=row["current_state"],
                next_state=next_state,
                details=payload,
            )
            conn.commit()
            return self.get_device(device_id)

    def list_events(self, device_id: str) -> list[dict[str, Any]]:
        with self.db.connect() as conn:
            if self._fetch_device(conn, device_id=device_id) is None:
                raise HTTPException(status_code=404, detail="Device not found")
            rows = conn.execute(
                "SELECT * FROM events WHERE device_id = ? ORDER BY id ASC",
                (device_id,),
            ).fetchall()
            return [
                {
                    "id": row["id"],
                    "deviceId": row["device_id"],
                    "eventType": row["event_type"],
                    "actor": row["actor"],
                    "previousState": row["previous_state"],
                    "nextState": row["next_state"],
                    "details": json.loads(row["details_json"]),
                    "createdAt": row["created_at"],
                }
                for row in rows
            ]

    def device_count(self) -> int:
        with self.db.connect() as conn:
            row = conn.execute("SELECT COUNT(*) AS count FROM devices").fetchone()
            return int(row["count"])
