from __future__ import annotations

from typing import Literal, Optional

from pydantic import BaseModel, Field, model_validator


DeviceState = Literal["registered", "normal", "pending_lock", "locked", "restricted", "recovered"]
UnlockProfile = Literal["2fa", "3fa"]
AgentAction = Literal["observe", "logout", "lock_session", "shutdown"]


class ClientRegisterRequest(BaseModel):
    deviceId: Optional[str] = None
    displayName: Optional[str] = None
    hwid: Optional[str] = None
    unlockProfile: UnlockProfile = "2fa"
    usbKeyId: Optional[str] = None


class ProvisioningBundle(BaseModel):
    deviceId: str
    emergencyId: str
    deviceSecret: str
    panicSecret: str
    unlockToken: str
    currentState: DeviceState
    unlockProfile: UnlockProfile
    userCanUnlock: bool


class ClientStatusResponse(BaseModel):
    deviceId: str
    currentState: DeviceState
    unlockProfile: UnlockProfile
    userCanUnlock: bool
    heartbeatIntervalSecond: int


class MobileStatusResponse(BaseModel):
    deviceId: str
    currentState: DeviceState
    userCanUnlock: bool
    needLockApproval: bool
    lockApprovalTimeSecond: int


class AdminRegisterRequest(BaseModel):
    deviceId: Optional[str] = None
    displayName: Optional[str] = None
    hwid: Optional[str] = None
    unlockProfile: UnlockProfile = "2fa"
    usbKeyId: Optional[str] = None
    userCanUnlock: bool = True
    agentAction: AgentAction = "observe"


class AdminUnlockRequest(BaseModel):
    deviceId: Optional[str] = None
    emergencyId: Optional[str] = None
    targetState: DeviceState = "recovered"

    @model_validator(mode="after")
    def validate_reference(self) -> "AdminUnlockRequest":
        if not self.deviceId and not self.emergencyId:
            raise ValueError("deviceId or emergencyId is required")
        return self


class AdminDevicePatchRequest(BaseModel):
    currentState: Optional[DeviceState] = None
    userCanUnlock: Optional[bool] = None
    agentAction: Optional[AgentAction] = None


class AdminDeviceResponse(BaseModel):
    deviceId: str
    emergencyId: str
    currentState: DeviceState
    displayName: Optional[str] = None
    hwid: Optional[str] = None
    unlockProfile: UnlockProfile
    usbKeyId: Optional[str] = None
    userCanUnlock: bool
    agentAction: AgentAction
    lastSeen: Optional[str] = None
    createdAt: str
    updatedAt: str


class EventRecord(BaseModel):
    id: int
    deviceId: str
    eventType: str
    actor: str
    previousState: Optional[DeviceState] = None
    nextState: Optional[DeviceState] = None
    details: dict = Field(default_factory=dict)
    createdAt: str


class AgentPollResponse(BaseModel):
    deviceId: str
    currentState: DeviceState
    action: AgentAction
    unlockProfile: UnlockProfile
    userCanUnlock: bool
    heartbeatIntervalSecond: int


class AgentAckRequest(BaseModel):
    action: AgentAction
    status: Literal["applied", "skipped", "failed"]
    note: Optional[str] = None


class HealthResponse(BaseModel):
    status: Literal["ok"]
    openapiPath: str
    deviceCount: int
