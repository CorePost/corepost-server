from __future__ import annotations

import hashlib
import hmac
from datetime import datetime, timezone


def canonical_message(method: str, path: str, timestamp: str) -> str:
    return "\n".join([method.upper(), path, timestamp])


def compute_signature(secret: str, method: str, path: str, timestamp: str) -> str:
    message = canonical_message(method, path, timestamp).encode()
    return hmac.new(secret.encode(), message, hashlib.sha256).hexdigest()


def timestamp_within_window(timestamp: str, window_seconds: int) -> bool:
    try:
        request_dt = datetime.fromtimestamp(int(timestamp), tz=timezone.utc)
    except (TypeError, ValueError):
        return False
    now = datetime.now(tz=timezone.utc)
    return abs((now - request_dt).total_seconds()) <= window_seconds


def verify_signature(secret: str, method: str, path: str, timestamp: str, signature: str, window_seconds: int) -> bool:
    if not timestamp_within_window(timestamp, window_seconds):
        return False
    expected = compute_signature(secret, method, path, timestamp)
    return hmac.compare_digest(expected, signature)
