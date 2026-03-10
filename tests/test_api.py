from __future__ import annotations

import time
from pathlib import Path

from fastapi.testclient import TestClient

from corepost_server.app import create_app
from corepost_server.config import Settings
from corepost_server.security import compute_signature


def build_client(tmp_path: Path) -> TestClient:
    settings = Settings(
        app_name="CorePost Server Test",
        host="test-host",
        port=8000,
        log_level="info",
        admin_token="test-admin",
        db_path=tmp_path / "corepost-test.db",
        require_registration_approval=False,
        require_hwid=False,
        require_lock_confirmation=True,
        lock_confirmation_window_seconds=30,
        hmac_window_seconds=5,
        heartbeat_interval_seconds=5,
        agent_action_when_locked="shutdown",
        agent_action_when_restricted="lock_session",
    )
    return TestClient(create_app(settings))


def auth_headers(secret: str, method: str, path: str, timestamp: int | None = None, header_name: str = "X-DeviceId", identity: str = "") -> dict[str, str]:
    ts = str(timestamp or int(time.time()))
    return {
        header_name: identity,
        "X-Timestamp": ts,
        "X-Signature": compute_signature(secret, method, path, ts),
    }


def provision_device(client: TestClient) -> dict:
    response = client.post("/client/register", json={"displayName": "demo-device", "unlockProfile": "3fa", "usbKeyId": "usb-demo"})
    assert response.status_code == 201
    return response.json()


def test_registration_heartbeat_and_decrypt(tmp_path: Path) -> None:
    client = build_client(tmp_path)
    bundle = provision_device(client)

    heartbeat = client.post(
        "/client/AmIOk",
        headers=auth_headers(bundle["deviceSecret"], "POST", "/client/AmIOk", identity=bundle["deviceId"]),
    )
    assert heartbeat.status_code == 200
    assert heartbeat.json()["currentState"] == "normal"
    assert heartbeat.json()["unlockProfile"] == "3fa"

    decrypt = client.get(
        "/client/decrypt",
        headers=auth_headers(bundle["deviceSecret"], "GET", "/client/decrypt", identity=bundle["deviceId"]),
    )
    assert decrypt.status_code == 200
    assert decrypt.text == bundle["unlockToken"]


def test_invalid_signature_is_rejected(tmp_path: Path) -> None:
    client = build_client(tmp_path)
    bundle = provision_device(client)
    response = client.post(
        "/client/AmIOk",
        headers={
            "X-DeviceId": bundle["deviceId"],
            "X-Timestamp": str(int(time.time())),
            "X-Signature": "bad-signature",
        },
    )
    assert response.status_code == 401


def test_stale_signature_is_rejected(tmp_path: Path) -> None:
    client = build_client(tmp_path)
    bundle = provision_device(client)
    stale_ts = int(time.time()) - 60
    response = client.post(
        "/client/AmIOk",
        headers=auth_headers(bundle["deviceSecret"], "POST", "/client/AmIOk", timestamp=stale_ts, identity=bundle["deviceId"]),
    )
    assert response.status_code == 401


def test_two_step_panic_lock_and_decrypt_denial(tmp_path: Path) -> None:
    client = build_client(tmp_path)
    bundle = provision_device(client)

    first = client.post(
        "/mobile/lock",
        headers=auth_headers(bundle["panicSecret"], "POST", "/mobile/lock", header_name="X-EmergencyId", identity=bundle["emergencyId"]),
    )
    assert first.status_code == 201
    assert first.json()["currentState"] == "pending_lock"

    second = client.post(
        "/mobile/lock",
        headers=auth_headers(bundle["panicSecret"], "POST", "/mobile/lock", header_name="X-EmergencyId", identity=bundle["emergencyId"]),
    )
    assert second.status_code == 200
    assert second.json()["currentState"] == "locked"

    decrypt = client.get(
        "/client/decrypt",
        headers=auth_headers(bundle["deviceSecret"], "GET", "/client/decrypt", identity=bundle["deviceId"]),
    )
    assert decrypt.status_code == 403


def test_mobile_unlock_policy_respected(tmp_path: Path) -> None:
    client = build_client(tmp_path)
    bundle = provision_device(client)

    client.patch(
        f"/admin/devices/{bundle['deviceId']}",
        headers={"X-Admin-Token": "test-admin"},
        json={"currentState": "locked", "userCanUnlock": False},
    )

    forbidden = client.post(
        "/mobile/unlock",
        headers=auth_headers(bundle["panicSecret"], "POST", "/mobile/unlock", header_name="X-EmergencyId", identity=bundle["emergencyId"]),
    )
    assert forbidden.status_code == 403

    client.patch(
        f"/admin/devices/{bundle['deviceId']}",
        headers={"X-Admin-Token": "test-admin"},
        json={"userCanUnlock": True},
    )
    allowed = client.post(
        "/mobile/unlock",
        headers=auth_headers(bundle["panicSecret"], "POST", "/mobile/unlock", header_name="X-EmergencyId", identity=bundle["emergencyId"]),
    )
    assert allowed.status_code == 200
    assert allowed.json()["currentState"] == "recovered"


def test_admin_unlock_and_repeated_lock_recover_cycle(tmp_path: Path) -> None:
    client = build_client(tmp_path)
    bundle = provision_device(client)

    for _ in range(2):
        client.post(
            "/mobile/lock",
            headers=auth_headers(bundle["panicSecret"], "POST", "/mobile/lock", header_name="X-EmergencyId", identity=bundle["emergencyId"]),
        )
        client.post(
            "/mobile/lock",
            headers=auth_headers(bundle["panicSecret"], "POST", "/mobile/lock", header_name="X-EmergencyId", identity=bundle["emergencyId"]),
        )
        unlock = client.post(
            "/admin/unlock",
            headers={"X-Admin-Token": "test-admin"},
            json={"deviceId": bundle["deviceId"], "targetState": "recovered"},
        )
        assert unlock.status_code == 200
        assert unlock.json()["currentState"] == "recovered"


def test_agent_poll_returns_policy(tmp_path: Path) -> None:
    client = build_client(tmp_path)
    bundle = provision_device(client)
    client.patch(
        f"/admin/devices/{bundle['deviceId']}",
        headers={"X-Admin-Token": "test-admin"},
        json={"currentState": "restricted", "agentAction": "logout"},
    )

    poll = client.post(
        "/agent/poll",
        headers=auth_headers(bundle["deviceSecret"], "POST", "/agent/poll", identity=bundle["deviceId"]),
    )
    assert poll.status_code == 200
    assert poll.json()["action"] == "lock_session"
    assert poll.json()["currentState"] == "restricted"


def test_admin_endpoints_list_devices_and_events(tmp_path: Path) -> None:
    client = build_client(tmp_path)
    bundle = provision_device(client)

    devices = client.get("/admin/devices", headers={"X-Admin-Token": "test-admin"})
    assert devices.status_code == 200
    assert devices.json()[0]["deviceId"] == bundle["deviceId"]

    events = client.get(f"/admin/devices/{bundle['deviceId']}/events", headers={"X-Admin-Token": "test-admin"})
    assert events.status_code == 200
    assert any(event["eventType"] == "client_registered" for event in events.json())
