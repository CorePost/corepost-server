#!/usr/bin/env python3
"""
This is the main backend server for the CorePost.
"""

import sqlite3
import secrets
import hmac
import hashlib
import configparser
from datetime import datetime
from typing import Optional

from fastapi import FastAPI, Header, HTTPException, Request, Depends, status
from fastapi.responses import PlainTextResponse, JSONResponse
from pydantic import BaseModel
import uvicorn


config = configparser.ConfigParser()
config.read("server.conf")
needRegistrationApproval = config.getboolean("server", "needRegistrationApproval", fallback=False)
needHWID = config.getboolean("server", "needHWID", fallback=False)
needLockApproval = config.getboolean("server", "needLockApproval", fallback=False)
lockApprovalTimeSecond = config.getint("server", "lockApprovalTimeSecond", fallback=30)
adminToken = config.get("server", "adminToken", fallback="supersecretadmin")
hmacWindow = config.getint("security", "hmacWindow", fallback=5)
host = config.get("server", "host", fallback="127.0.0.1")
port = config.getint("server", "port", fallback=8000)

DB_PATH = "devices.db"

def init_db():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS devices (
            deviceId TEXT PRIMARY KEY,
            emergencyId TEXT NOT NULL,
            emergencyState INTEGER DEFAULT 0,
            token TEXT NOT NULL,
            lastSeen DATETIME,
            hwid TEXT,
            pendingLockTime DATETIME,
            userCanUnlock INTEGER DEFAULT 1
        )
    """)
    conn.commit()
    conn.close()

init_db()

def get_db_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def verify_hmac(secret: str, timestamp: str, signature: str) -> bool:
    """
    Verify that the provided HMAC signature matches the expected HMAC for the given timestamp.
    Uses SHA256 and compares in constant time.
    """
    try:
        req_time = datetime.fromtimestamp(int(timestamp))
    except Exception:
        return False
    now = datetime.now()
    if abs((now - req_time).total_seconds()) > hmacWindow:
        return False
    message = timestamp
    expected = hmac.new(secret.encode(), message.encode(), hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, signature)

def get_client_device(deviceId: str):
    """
    Retrieve a device record from the database using deviceId.
    """
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("SELECT * FROM devices WHERE deviceId = ?", (deviceId,))
    row = cur.fetchone()
    conn.close()
    return row

def get_mobile_device_by_emergency(emergencyId: str):
    """
    Retrieve a device record from the database using emergencyId.
    """
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("SELECT * FROM devices WHERE emergencyId = ?", (emergencyId,))
    row = cur.fetchone()
    conn.close()
    return row


app = FastAPI(title="CorePost Server", version="1.0")

async def verifyClientAuth(
    x_deviceid: str = Header(..., alias="X-DeviceId"),
    x_timestamp: str = Header(..., alias="X-Timestamp"),
    x_signature: str = Header(..., alias="X-Signature")
):
    """
    Dependency to verify HMAC authentication for client endpoints.
    Retrieves the device's token from the database and uses it to verify the signature.
    Raises HTTPException if verification fails.
    """
    device = get_client_device(x_deviceid)
    if device is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Device not found")
    token = device["token"]
    if not verify_hmac(token, x_timestamp, x_signature):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid HMAC signature")
    return device

async def verifyMobileAuth(
    x_emergencyid: str = Header(..., alias="X-EmergencyId"),
    x_timestamp: str = Header(..., alias="X-Timestamp"),
    x_signature: str = Header(..., alias="X-Signature")
):
    """
    Dependency to verify HMAC authentication for mobile endpoints.
    Retrieves the device's token using emergencyId and uses it to verify the signature.
    """
    device = get_mobile_device_by_emergency(x_emergencyid)
    if device is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Device not found")
    token = device["token"]
    if not verify_hmac(token, x_timestamp, x_signature):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid HMAC signature")
    return device

def verifyAdmin(admin_token: str):
    """
    Verify that the provided admin token matches the configured adminToken.
    """
    if admin_token != adminToken:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid admin token")

# Pydantic models for request bodies
class ClientRegisterRequest(BaseModel):
    deviceId: Optional[str] = None
    hwid: Optional[str] = None

class AdminRegisterResponse(BaseModel):
    deviceId: str

class AdminUnlockRequest(BaseModel):
    deviceId: Optional[str] = None
    emergencyId: Optional[str] = None

@app.post("/client/register")
async def clientRegister(requestBody: ClientRegisterRequest):
    """
    Register a new device.
    If needRegistrationApproval is True, the request must include a deviceId that already exists in the database.
    Otherwise, a new device record is created with randomly generated deviceId, emergencyId, and token.
    Returns the deviceId, emergencyId, and token.
    """
    conn = get_db_connection()
    cur = conn.cursor()
    now = datetime.now().isoformat()

    if needRegistrationApproval:
        # Registration requires that deviceId is provided and exists in DB
        if not requestBody.deviceId:
            conn.close()
            raise HTTPException(status_code=400, detail="deviceId is required for registration approval")
        cur.execute("SELECT * FROM devices WHERE deviceId = ?", (requestBody.deviceId,))
        row = cur.fetchone()
        if row is None:
            conn.close()
            raise HTTPException(status_code=404, detail="Device not pre-registered")
        if needHWID:
            if not requestBody.hwid:
                conn.close()
                raise HTTPException(status_code=400, detail="HWID is required")
            cur.execute("UPDATE devices SET lastSeen = ?, hwid = ? WHERE deviceId = ?", (now, requestBody.hwid, requestBody.deviceId))
        else:
            cur.execute("UPDATE devices SET lastSeen = ? WHERE deviceId = ?", (now, requestBody.deviceId))
        conn.commit()
        device = get_client_device(requestBody.deviceId)
        conn.close()
        return {
            "deviceId": device["deviceId"],
            "emergencyId": device["emergencyId"],
            "token": device["token"]
        }
    else:
        # Automatically register new device
        newDeviceId = secrets.token_hex(8)
        newEmergencyId = secrets.token_hex(8)
        newToken = secrets.token_hex(32)
        if needHWID:
            if not requestBody.hwid:
                conn.close()
                raise HTTPException(status_code=400, detail="HWID is required")
        hwid = requestBody.hwid if needHWID else None
        try:
            cur.execute("""
                INSERT INTO devices (deviceId, emergencyId, token, lastSeen, hwid)
                VALUES (?, ?, ?, ?, ?)
            """, (newDeviceId, newEmergencyId, newToken, now, hwid))
            conn.commit()
        except Exception as e:
            conn.close()
            raise HTTPException(status_code=500, detail="Database error")
        conn.close()
        return {
            "deviceId": newDeviceId,
            "emergencyId": newEmergencyId,
            "token": newToken
        }


@app.post("/client/AmIOk")
async def clientAmIOk(device=Depends(verifyClientAuth)):
    """
    Endpoint for an existing device to check its status.
    Updates the lastSeen timestamp.
    If emergencyState is False, returns 200 OK.
    If emergencyState is True, returns an error indicating the device is stolen.
    """
    deviceId = device["deviceId"]
    now = datetime.now().isoformat()
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("UPDATE devices SET lastSeen = ? WHERE deviceId = ?", (now, deviceId))
    conn.commit()
    cur.execute("SELECT emergencyState FROM devices WHERE deviceId = ?", (deviceId,))
    row = cur.fetchone()
    conn.close()
    if row and row["emergencyState"] == 0:
        return {"status": "ok"}
    else:
        raise HTTPException(status_code=403, detail="Device marked as stolen")



@app.get("/client/decrypt", response_class=PlainTextResponse)
async def clientDecrypt(device=Depends(verifyClientAuth)):
    """
    Endpoint for a device to retrieve its decryption token.
    Returns the token as plain text if the device is not marked as stolen.
    """
    deviceId = device["deviceId"]
    if device["emergencyState"] != 0:
        raise HTTPException(status_code=403, detail="Device marked as stolen")
    return device["token"]


@app.get("/mobile/check")
async def mobileCheck(device=Depends(verifyMobileAuth)):
    """
    Endpoint for mobile app to check the emergency (panic) status.
    Returns the emergencyState, and configuration parameters needLockApproval and lockApprovalTimeSecond.
    """
    return {
        "emergencyState": bool(device["emergencyState"]),
        "needLockApproval": needLockApproval,
        "lockApprovalTimeSecond": lockApprovalTimeSecond
    }


@app.post("/mobile/lock")
async def mobileLock(device=Depends(verifyMobileAuth)):
    """
    Endpoint for mobile app to request locking (i.e., marking device as stolen).
    If needLockApproval is true, a two-step confirmation is required.
    On the first request, if no pending lock exists, set pendingLockTime and return 201.
    On a subsequent request within the approval window, set emergencyState to true and return 200.
    """
    deviceId = device["deviceId"]
    now = datetime.now()
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("SELECT pendingLockTime FROM devices WHERE deviceId = ?", (deviceId,))
    row = cur.fetchone()
    if row is None:
        conn.close()
        raise HTTPException(status_code=404, detail="Device not found")
    pendingLockTime = row["pendingLockTime"]
    if needLockApproval:
        if pendingLockTime is None:
            # First lock request: record time and ask to confirm
            cur.execute("UPDATE devices SET pendingLockTime = ? WHERE deviceId = ?", (now.isoformat(), deviceId))
            conn.commit()
            conn.close()
            return JSONResponse(status_code=201, content={"detail": "Lock request received. Please confirm within the approval window."})
        else:
            prevTime = datetime.fromisoformat(pendingLockTime)
            if (now - prevTime).total_seconds() <= lockApprovalTimeSecond:
                # Confirm lock: mark emergencyState true and clear pendingLockTime
                cur.execute("UPDATE devices SET emergencyState = 1, pendingLockTime = NULL, lastSeen = ? WHERE deviceId = ?", (now.isoformat(), deviceId))
                conn.commit()
                conn.close()
                return {"detail": "Device locked (stolen)"}
            else:
                # Approval window expired, reset pendingLockTime and ask to try again
                cur.execute("UPDATE devices SET pendingLockTime = ? WHERE deviceId = ?", (now.isoformat(), deviceId))
                conn.commit()
                conn.close()
                return JSONResponse(status_code=201, content={
                    "detail": "Lock request received. Please confirm within the approval window."})
    else:
        # No lock approval required, immediately mark device as stolen
        cur.execute("UPDATE devices SET emergencyState = 1, lastSeen = ? WHERE deviceId = ?", (now.isoformat(), deviceId))
        conn.commit()
        conn.close()
        return {"detail": "Device locked (stolen)"}


@app.post("/mobile/unlock")
async def mobileUnlock(device=Depends(verifyMobileAuth)):
    """
    Endpoint for mobile app to request unlocking (i.e., clearing the emergency state).
    If the device is allowed to unlock (userCanUnlock is true), and if needLockApproval is true,
    require a two-step confirmation similar to /mobile/lock.
    Otherwise, immediately clear emergencyState.
    """
    deviceId = device["deviceId"]
    now = datetime.now()
    conn = get_db_connection()
    cur = conn.cursor()
    # Check if device is allowed to unlock
    if device["userCanUnlock"] == 0:
        conn.close()
        raise HTTPException(status_code=403, detail="Device is not allowed to unlock")
    if needLockApproval:
        cur.execute("SELECT pendingLockTime FROM devices WHERE deviceId = ?", (deviceId,))
        row = cur.fetchone()
        pendingLockTime = row["pendingLockTime"]
        if pendingLockTime is None:
            cur.execute("UPDATE devices SET pendingLockTime = ? WHERE deviceId = ?", (now.isoformat(), deviceId))
            conn.commit()
            conn.close()
            return JSONResponse(status_code=201, content={"detail": "Unlock request received. Please confirm within the approval window."})
        else:
            prevTime = datetime.fromisoformat(pendingLockTime)
            if (now - prevTime).total_seconds() <= lockApprovalTimeSecond:
                cur.execute("UPDATE devices SET emergencyState = 0, pendingLockTime = NULL, lastSeen = ? WHERE deviceId = ?", (now.isoformat(), deviceId))
                conn.commit()
                conn.close()
                return {"detail": "Device unlocked"}
            else:
                cur.execute("UPDATE devices SET pendingLockTime = NULL WHERE deviceId = ?", (deviceId,))
                conn.commit()
                conn.close()
                raise HTTPException(status_code=408, detail="Unlock approval timeout. Please try again.")
    else:
        cur.execute("UPDATE devices SET emergencyState = 0, lastSeen = ? WHERE deviceId = ?", (now.isoformat(), deviceId))
        conn.commit()
        conn.close()
        return {"detail": "Device unlocked"}


@app.post("/admin/register", response_model=AdminRegisterResponse)
async def adminRegister(request: Request):
    """
    Admin endpoint to register a new device.
    Requires the correct ADMIN_TOKEN provided as a query parameter (or header).
    Creates a new device record with random data and returns only the deviceId.
    """
    admin_token = request.headers.get("X-Admin-Token")
    if admin_token != adminToken:
        raise HTTPException(status_code=401, detail="Invalid admin token")
    conn = get_db_connection()
    cur = conn.cursor()
    newDeviceId = secrets.token_hex(8)
    newEmergencyId = secrets.token_hex(8)
    newToken = secrets.token_hex(32)
    now = datetime.now().isoformat()
    try:
        cur.execute("""
            INSERT INTO devices (deviceId, emergencyId, token, lastSeen, emergencyState)
            VALUES (?, ?, ?, ?, 0)
        """, (newDeviceId, newEmergencyId, newToken, now))
        conn.commit()
    except Exception as e:
        conn.close()
        raise HTTPException(status_code=500, detail="Database error")
    conn.close()
    return AdminRegisterResponse(deviceId=newDeviceId)


@app.post("/admin/unlock")
async def adminUnlock(request: Request, unlockRequest: AdminUnlockRequest):
    """
    Admin endpoint to unlock a device (clear emergency state).
    Requires ADMIN_TOKEN for authentication.
    Accepts either deviceId or emergencyId (emergencyId has priority).
    """
    admin_token = request.headers.get("X-Admin-Token")
    if admin_token != adminToken:
        raise HTTPException(status_code=401, detail="Invalid admin token")
    conn = get_db_connection()
    cur = conn.cursor()
    if unlockRequest.emergencyId:
        cur.execute("UPDATE devices SET emergencyState = 0, lastSeen = ? WHERE emergencyId = ?", (datetime.now().isoformat(), unlockRequest.emergencyId))
    elif unlockRequest.deviceId:
        cur.execute("UPDATE devices SET emergencyState = 0, lastSeen = ? WHERE deviceId = ?", (datetime.now().isoformat(), unlockRequest.deviceId))
    else:
        conn.close()
        raise HTTPException(status_code=400, detail="Must provide deviceId or emergencyId")
    if cur.rowcount == 0:
        conn.close()
        raise HTTPException(status_code=404, detail="Device not found")
    conn.commit()
    conn.close()
    return {"detail": "Device unlocked by admin"}


if __name__ == "__main__":
    uvicorn.run(app, host=host, port=port)
