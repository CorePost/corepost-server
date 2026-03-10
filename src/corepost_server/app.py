from __future__ import annotations

from fastapi import Depends, FastAPI, Header, HTTPException, Request, Response, status
from fastapi.responses import PlainTextResponse

from corepost_server.config import Settings, get_settings
from corepost_server.schemas import (
    AdminDevicePatchRequest,
    AdminDeviceResponse,
    AdminRegisterRequest,
    AdminUnlockRequest,
    AgentAckRequest,
    AgentPollResponse,
    ClientRegisterRequest,
    ClientStatusResponse,
    EventRecord,
    HealthResponse,
    MobileStatusResponse,
    ProvisioningBundle,
)
from corepost_server.security import verify_signature
from corepost_server.service import CorePostService


def create_app(settings: Settings | None = None) -> FastAPI:
    resolved_settings = settings or get_settings()
    service = CorePostService(resolved_settings)

    app = FastAPI(
        title=resolved_settings.app_name,
        version="0.1.0",
        description="CorePost control plane for preboot unlock, mobile panic-lock and post-boot agent policies.",
    )
    app.state.service = service
    app.state.settings = resolved_settings

    def get_service(request: Request) -> CorePostService:
        return request.app.state.service

    def get_settings_dep(request: Request) -> Settings:
        return request.app.state.settings

    def verify_admin(x_admin_token: str = Header(..., alias="X-Admin-Token"), settings: Settings = Depends(get_settings_dep)) -> None:
        if x_admin_token != settings.admin_token:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid admin token")

    def verify_device_request(
        request: Request,
        x_deviceid: str = Header(..., alias="X-DeviceId"),
        x_timestamp: str = Header(..., alias="X-Timestamp"),
        x_signature: str = Header(..., alias="X-Signature"),
        service: CorePostService = Depends(get_service),
        settings: Settings = Depends(get_settings_dep),
    ) -> str:
        row = service.authenticate_device(x_deviceid)
        if not verify_signature(row["device_secret"], request.method, request.url.path, x_timestamp, x_signature, settings.hmac_window_seconds):
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid HMAC signature")
        return row["device_id"]

    def verify_mobile_request(
        request: Request,
        x_emergencyid: str = Header(..., alias="X-EmergencyId"),
        x_timestamp: str = Header(..., alias="X-Timestamp"),
        x_signature: str = Header(..., alias="X-Signature"),
        service: CorePostService = Depends(get_service),
        settings: Settings = Depends(get_settings_dep),
    ) -> str:
        row = service.authenticate_emergency(x_emergencyid)
        if not verify_signature(row["panic_secret"], request.method, request.url.path, x_timestamp, x_signature, settings.hmac_window_seconds):
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid HMAC signature")
        return row["emergency_id"]

    @app.get("/healthz", response_model=HealthResponse)
    async def health(service: CorePostService = Depends(get_service)) -> HealthResponse:
        return HealthResponse(status="ok", openapiPath="/openapi.json", deviceCount=service.device_count())

    @app.post("/client/register", response_model=ProvisioningBundle, status_code=status.HTTP_201_CREATED)
    async def client_register(payload: ClientRegisterRequest, service: CorePostService = Depends(get_service)) -> ProvisioningBundle:
        return ProvisioningBundle(**service.register_client(payload.model_dump()))

    @app.post("/client/AmIOk", response_model=ClientStatusResponse)
    async def client_am_i_ok(device_id: str = Depends(verify_device_request), service: CorePostService = Depends(get_service)) -> ClientStatusResponse:
        return ClientStatusResponse(**service.client_status(device_id))

    @app.post("/client/heartbeat", response_model=ClientStatusResponse)
    async def client_heartbeat(device_id: str = Depends(verify_device_request), service: CorePostService = Depends(get_service)) -> ClientStatusResponse:
        return ClientStatusResponse(**service.client_status(device_id))

    @app.get("/client/decrypt", response_class=PlainTextResponse)
    async def client_decrypt(device_id: str = Depends(verify_device_request), service: CorePostService = Depends(get_service)) -> PlainTextResponse:
        return PlainTextResponse(service.client_decrypt(device_id))

    @app.get("/mobile/check", response_model=MobileStatusResponse)
    async def mobile_check(emergency_id: str = Depends(verify_mobile_request), service: CorePostService = Depends(get_service)) -> MobileStatusResponse:
        return MobileStatusResponse(**service.mobile_check(emergency_id))

    @app.post("/mobile/lock")
    async def mobile_lock(response: Response, emergency_id: str = Depends(verify_mobile_request), service: CorePostService = Depends(get_service)) -> dict:
        code, payload = service.mobile_lock(emergency_id)
        response.status_code = code
        return payload

    @app.post("/mobile/unlock")
    async def mobile_unlock(emergency_id: str = Depends(verify_mobile_request), service: CorePostService = Depends(get_service)) -> dict:
        return service.mobile_unlock(emergency_id)

    @app.post("/agent/poll", response_model=AgentPollResponse)
    async def agent_poll(device_id: str = Depends(verify_device_request), service: CorePostService = Depends(get_service)) -> AgentPollResponse:
        return AgentPollResponse(**service.agent_poll(device_id))

    @app.post("/agent/ack")
    async def agent_ack(payload: AgentAckRequest, device_id: str = Depends(verify_device_request), service: CorePostService = Depends(get_service)) -> dict:
        return service.agent_ack(device_id, payload.model_dump())

    @app.post("/admin/register", response_model=ProvisioningBundle, status_code=status.HTTP_201_CREATED, dependencies=[Depends(verify_admin)])
    async def admin_register(payload: AdminRegisterRequest, service: CorePostService = Depends(get_service)) -> ProvisioningBundle:
        return ProvisioningBundle(**service.register_admin(payload.model_dump()))

    @app.post("/admin/unlock", dependencies=[Depends(verify_admin)])
    async def admin_unlock(payload: AdminUnlockRequest, service: CorePostService = Depends(get_service)) -> dict:
        return service.admin_unlock(payload.model_dump())

    @app.post("/admin/lock", dependencies=[Depends(verify_admin)])
    async def admin_lock(payload: AdminUnlockRequest, service: CorePostService = Depends(get_service)) -> dict:
        return service.admin_unlock(payload.model_copy(update={"targetState": "locked"}).model_dump())

    @app.post("/admin/recover", dependencies=[Depends(verify_admin)])
    async def admin_recover(payload: AdminUnlockRequest, service: CorePostService = Depends(get_service)) -> dict:
        return service.admin_unlock(payload.model_copy(update={"targetState": "recovered"}).model_dump())

    @app.post("/admin/restrict", dependencies=[Depends(verify_admin)])
    async def admin_restrict(payload: AdminUnlockRequest, service: CorePostService = Depends(get_service)) -> dict:
        return service.admin_unlock(payload.model_copy(update={"targetState": "restricted"}).model_dump())

    @app.get("/admin/devices", response_model=list[AdminDeviceResponse], dependencies=[Depends(verify_admin)])
    async def list_devices(service: CorePostService = Depends(get_service)) -> list[AdminDeviceResponse]:
        return [AdminDeviceResponse(**row) for row in service.list_devices()]

    @app.get("/admin/devices/{device_id}", response_model=AdminDeviceResponse, dependencies=[Depends(verify_admin)])
    async def get_device(device_id: str, service: CorePostService = Depends(get_service)) -> AdminDeviceResponse:
        return AdminDeviceResponse(**service.get_device(device_id))

    @app.patch("/admin/devices/{device_id}", response_model=AdminDeviceResponse, dependencies=[Depends(verify_admin)])
    async def patch_device(device_id: str, payload: AdminDevicePatchRequest, service: CorePostService = Depends(get_service)) -> AdminDeviceResponse:
        return AdminDeviceResponse(**service.patch_device(device_id, payload.model_dump(exclude_none=True)))

    @app.get("/admin/devices/{device_id}/events", response_model=list[EventRecord], dependencies=[Depends(verify_admin)])
    async def list_events(device_id: str, service: CorePostService = Depends(get_service)) -> list[EventRecord]:
        return [EventRecord(**row) for row in service.list_events(device_id)]

    return app


app = create_app()
