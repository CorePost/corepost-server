# CorePost Server

Сервер управления состоянием устройств для CorePost. Компонент реализует:

- регистрацию и выдачу provisioning bundle для install/preboot/mobile/agent;
- предзагрузочный допуск к расшифровке через `/client/decrypt`;
- panic-lock и пользовательскую разблокировку через mobile API;
- post-boot polling/policy для `corepost-agent`;
- административное управление, журнал событий и OpenAPI.

## Контракт безопасности

Сервер использует HMAC-SHA256 для device- и mobile-запросов.

- Device/preboot/agent используют `deviceSecret`.
- Mobile panic client использует `panicSecret`.
- Предзагрузочный токен расшифровки отдается отдельно как `unlockToken` через `/client/decrypt`.

Подписываемое сообщение:

```text
{HTTP_METHOD}
{PATH}
{UNIX_TIMESTAMP}
```

Обязательные заголовки:

- `X-DeviceId` или `X-EmergencyId`
- `X-Timestamp`
- `X-Signature`

Административные запросы используют `X-Admin-Token`.

## Состояния устройства

- `registered` — устройство зарегистрировано, но еще не прошло штатный рабочий цикл.
- `normal` — штатное состояние, preboot и agent работают нормально.
- `pending_lock` — идет окно подтверждения panic-lock.
- `locked` — deny-by-default для preboot, агент получает жесткую реакцию.
- `restricted` — устройство ограничено, агент должен применить мягкую реакцию.
- `recovered` — состояние после восстановления доступа.

## API

Основные endpoint-ы:

- `POST /client/register`
- `POST /client/AmIOk`
- `GET /client/decrypt`
- `GET /mobile/check`
- `POST /mobile/lock`
- `POST /mobile/unlock`
- `POST /agent/poll`
- `POST /agent/ack`
- `POST /admin/register`
- `POST /admin/unlock`
- `GET /admin/devices`
- `PATCH /admin/devices/{device_id}`
- `GET /admin/devices/{device_id}/events`
- `GET /healthz`
- `GET /openapi.json`

## Локальный запуск

```bash
cd corepost-server
python3 -m venv .venv
source .venv/bin/activate
pip install -e .[dev]
cp .env.example .env
set -a
source .env
set +a
python main.py
```

Сервер слушает `COREPOST_PORT`, а OpenAPI публикуется по пути `COREPOST_OPENAPI_PATH`.

## Тесты

```bash
cd corepost-server
python3 -m venv .venv
source .venv/bin/activate
pip install -e .[dev]
pytest
```

Покрыты ключевые сценарии:

- регистрация;
- штатный heartbeat/decrypt;
- неверная подпись;
- просроченная подпись;
- двухшаговый panic-lock;
- запрет decrypt после lock;
- user unlock allowed/forbidden;
- повторные циклы lock/recover;
- post-boot agent policy;
- admin device listing и event log.

## Docker Compose

```bash
cd corepost-server
cp .env.example .env
set -a
source .env
set +a
docker compose up --build --wait -d
docker compose ps
python - <<'PY'
import http.client
import os

conn = http.client.HTTPConnection(
    os.environ["COREPOST_HEALTHCHECK_HOST"],
    int(os.environ["COREPOST_SERVER_PORT"]),
    timeout=3,
)
conn.request("GET", os.environ["COREPOST_HEALTHCHECK_PATH"])
print(conn.getresponse().read().decode())
PY
```

Для smoke-проверок используйте `COREPOST_HEALTHCHECK_HOST`, `COREPOST_SERVER_PORT` и `COREPOST_HEALTHCHECK_PATH`.
OpenAPI доступен на том же host/port по пути `COREPOST_OPENAPI_PATH`.

Для независимых инстансов достаточно менять:

- `COREPOST_PROJECT_NAME`
- `COREPOST_CONTAINER_NAME`
- `COREPOST_SERVER_PORT`
- `COREPOST_ADMIN_TOKEN`
- `COREPOST_DATA_DIR`

Это позволяет поднять отдельные серверы под preboot, agent, mobile-android и mobile-ios.

Готовые шаблоны уже лежат в:

- `docker/instances/preboot.env`
- `docker/instances/agent.env`
- `docker/instances/mobile-android.env`
- `docker/instances/mobile-ios.env`

Команды запуска и остановки:

```bash
./docker/launch-instance.sh preboot
./docker/launch-instance.sh agent
./docker/launch-instance.sh mobile-android
./docker/launch-instance.sh mobile-ios

./docker/stop-instance.sh preboot
```
