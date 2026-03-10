from __future__ import annotations

import os
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path


def _read_bool(name: str, default: bool) -> bool:
    value = os.getenv(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def _read_int(name: str, default: int) -> int:
    value = os.getenv(name)
    if value is None:
        return default
    return int(value)


@dataclass(frozen=True)
class Settings:
    app_name: str
    host: str
    port: int
    log_level: str
    admin_token: str
    db_path: Path
    require_registration_approval: bool
    require_hwid: bool
    require_lock_confirmation: bool
    lock_confirmation_window_seconds: int
    hmac_window_seconds: int
    heartbeat_interval_seconds: int
    agent_action_when_locked: str
    agent_action_when_restricted: str

    @classmethod
    def from_env(cls) -> "Settings":
        data_root = Path(os.getenv("COREPOST_DATA_DIR", ".")).resolve()
        db_path = Path(os.getenv("COREPOST_DB_PATH", str(data_root / "corepost.db"))).resolve()
        db_path.parent.mkdir(parents=True, exist_ok=True)

        return cls(
            app_name="CorePost Server",
            host=os.getenv("COREPOST_HOST", "0.0.0.0"),
            port=_read_int("COREPOST_PORT", 8000),
            log_level=os.getenv("COREPOST_LOG_LEVEL", "info"),
            admin_token=os.getenv("COREPOST_ADMIN_TOKEN", "change-me-corepost-admin"),
            db_path=db_path,
            require_registration_approval=_read_bool("COREPOST_REQUIRE_REGISTRATION_APPROVAL", False),
            require_hwid=_read_bool("COREPOST_REQUIRE_HWID", False),
            require_lock_confirmation=_read_bool("COREPOST_REQUIRE_LOCK_CONFIRMATION", True),
            lock_confirmation_window_seconds=_read_int("COREPOST_LOCK_CONFIRMATION_WINDOW_SECONDS", 30),
            hmac_window_seconds=_read_int("COREPOST_HMAC_WINDOW_SECONDS", 5),
            heartbeat_interval_seconds=_read_int("COREPOST_HEARTBEAT_INTERVAL_SECONDS", 5),
            agent_action_when_locked=os.getenv("COREPOST_AGENT_ACTION_WHEN_LOCKED", "shutdown"),
            agent_action_when_restricted=os.getenv("COREPOST_AGENT_ACTION_WHEN_RESTRICTED", "lock_session"),
        )


@lru_cache
def get_settings() -> Settings:
    return Settings.from_env()


def load_settings() -> Settings:
    return get_settings()
