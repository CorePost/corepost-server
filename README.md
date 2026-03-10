# CorePost Server Backend Documentation

*Data leaks don't ask permission.*

---

## 🇷🇺 Описание проекта

**CorePost** — это модульная, открытая система безопасности, предназначенная для защиты корпоративных устройств от несанкционированного доступа, утечек данных и краж. Серверная часть является центральным компонентом CorePost и отвечает за:

- **Регистрацию устройств и управление токенами**: выдача защищённых токенов для расшифровки диска.
- **Управление тревогой**: возможность удалённой пометки устройств как “украденные” через API тревоги.
- **Мониторинг статуса**: позволяет устройствам и мобильным приложениям проверять их текущий статус безопасности.
- **Администрирование**: предоставляет администраторам возможность разблокировать или регистрировать устройства через защищённый интерфейс администратора.

Этот сервер построен с использованием **Python**, **FastAPI** и **SQLite**.

---

## Технические детали

### Архитектура

Серверная часть предоставляет REST API со следующими основными конечными точками:
- `/client/register`
- `/client/AmIOk`
- `/client/decrypt`
- `/mobile/check`
- `/mobile/lock`
- `/mobile/unlock`
- `/admin/register`
- `/admin/unlock`

Для защиты чувствительных конечных точек используется HMAC-аутентификация. Клиенты (как устройства, так и мобильные приложения) должны включать определённые заголовки (например, `X-DeviceId`, `X-Timestamp`, `X-Signature`) в каждый запрос. HMAC-подпись вычисляется с использованием общего секрета (токена устройства) и временной метки запроса для защиты от атак повторного воспроизведения.

### Схема базы данных

База данных SQLite (`devices.db`) содержит таблицу `devices` со следующими столбцами:

| Название столбца    | Тип        | Описание |
|---------------------|------------|----------|
| `deviceId`          | TEXT       | Уникальный буквенно-цифровой идентификатор устройства (первичный ключ). |
| `emergencyId`       | TEXT       | Случайный хэш, используемый для операций тревоги (аварийных). |
| `emergencyState`    | INTEGER    | Булев флаг (0 или 1), указывающий, находится ли устройство в режиме тревоги. |
| `token`             | TEXT       | Безопасный случайный токен, используемый для расшифровки и HMAC-аутентификации. Рекомендуемая длина — 64 шестнадцатеричных символа (256 бит). |
| `lastSeen`          | DATETIME   | Временная метка последнего успешного сигнала от устройства. |
| `hwid`              | TEXT       | (Необязательно) Аппаратный идентификатор, если требуется конфигурацией. |
| `pendingLockTime`   | DATETIME   | Временная метка ожидающих запросов на блокировку, если требуется одобрение. |
| `userCanUnlock`     | INTEGER    | Булев флаг (1 или 0), указывающий, разрешено ли устройству разблокироваться удалённо. |

База данных автоматически инициализируется, если она не существует при запуске сервера.

---

## Соображения безопасности

### HMAC-аутентификация
- **Защита от повторов:** Каждый запрос должен включать временную метку (`X-Timestamp`) и HMAC-подпись (`X-Signature`). Сервер проверяет, что временная метка находится в пределах настраиваемого временного окна (по умолчанию 5 секунд), чтобы предотвратить атаки повторного воспроизведения.
- **Надёжность токена:** Токен устройства создаётся как 64-символьная шестнадцатеричная строка (256 бит энтропии), что делает атаки перебора невозможными.
- **Привязка к устройству:** При регистрации может быть дополнительно запрошен аппаратный ID (`hwid`), добавляя дополнительный фактор к идентификации устройства.
- **Безопасность транспорта:** Все конечные точки должны быть доступны только через HTTPS. Сертификаты управляются на стороне сервера, и ожидается, что клиенты (мобильные/настольные) будут их проверять.

### Безопасность отдельных конечных точек
- **Точка регистрации (`/client/register`):**  
  Если `needRegistrationApproval` включен, устройство должно быть предварительно зарегистрировано (его `deviceId` должен уже существовать в базе данных) и при необходимости предоставить `hwid`. В противном случае будет возвращена ошибка.  
  Если `needRegistrationApproval` выключен, создаётся новая запись устройства автоматически.
- **Точка сигналов (`/client/AmIOk`):**  
  Устройство должно аутентифицироваться и обновить временную метку `lastSeen`. Если устройство помечено как украденное (`emergencyState = 1`), запрос отклоняется.
- **Точка расшифровки (`/client/decrypt`):**  
  Возвращает токен расшифровки в открытом виде, только если устройство не помечено как украденное.
- **Мобильные точки (`/mobile/check`, `/mobile/lock`, `/mobile/unlock`):**  
  Эти конечные точки используют `emergencyId` для аутентификации и управляют тревожным состоянием. Если включён `needLockApproval`, применяется двухэтапный процесс подтверждения, чтобы избежать случайной блокировки/разблокировки.
- **Административные точки (`/admin/register`, `/admin/unlock`):**  
  Защищены секретным токеном администратора, передаваемым в заголовке. Эти конечные точки позволяют администратору регистрировать новые устройства (для подтверждения) или разблокировать устройство.

---

## Запуск сервера

### Предварительные требования
- Установлен Python 3.8+
- Установлены зависимости (см. `requirements.txt`, если предоставлен, или установить через pip)
- Установлен SQLite3 (обычно включён в стандартные дистрибутивы Linux)
- FastAPI и Uvicorn (`pip install fastapi uvicorn`)

### Как запустить
1. **Конфигурация:**  
   Создайте конфигурационный файл `server.conf` в той же директории, где находится сервер. Пример конфигурации приведён ниже.

2. **Инициализация базы данных:**  
   Код сервера автоматически инициализирует базу данных SQLite (`devices.db`) и создаёт таблицу `devices`, если она не существует.

3. **Запуск сервера:**  
   Запустите серверную часть с помощью:
   ```bash
   uvicorn backend:app --host 0.0.0.0 --port 8000
   ```

4. **Рекомендации при выпуске в production**  
   - Используйте менеджер процессов (например, `gunicorn` с воркерами Uvicorn) в продакшене.
   - Защитите токен администратора и убедитесь, что всё взаимодействие происходит по HTTPS.

---

## Пример конфигурационного файла (`server.conf`)

```ini
[server]
needRegistrationApproval = false
needHWID = false
needLockApproval = true
lockApprovalTimeSecond = 30
adminToken = supersecretadmin

[security]
hmacWindow = 5
```

---

## Документация по конечным точкам

### `/client/register` (POST)
- **Назначение:** Регистрация нового устройства.
- **Поведение:**
  - Если `needRegistrationApproval` установлено в `true`, запрос должен содержать предварительно зарегистрированный `deviceId` (и при необходимости `hwid`, если `needHWID` включён). Если не найдено — возвращается ошибка.
  - Если `needRegistrationApproval` установлено в `false`, создаётся новая запись со случайными значениями:
    - `deviceId`: 16 шестнадцатеричных символов (8 байт)
    - `emergencyId`: 16 шестнадцатеричных символов (8 байт)
    - `token`: 64 шестнадцатеричных символа (32 байта)
    - `emergencyState`: устанавливается в 0
    - `lastSeen`: текущая временная метка
- **Ответ:** JSON с `deviceId`, `emergencyId` и `token`.

### `/client/AmIOk` (POST)
- **Назначение:** Конечная точка сигналов для устройств.
- **Поведение:**  
  Обновляет временную метку `lastSeen`. Возвращает 200 OK, если `emergencyState` = false; иначе — 403, устройство помечено как украденное.
- **Аутентификация:** HMAC через заголовки `X-DeviceId`, `X-Timestamp` и `X-Signature`.

### `/client/decrypt` (GET)
- **Назначение:** Получение токена расшифровки.
- **Поведение:**  
  Возвращает токен устройства в открытом виде, если `emergencyState` = false; иначе — 403.
- **Аутентификация:** HMAC, как выше.

### `/mobile/check` (GET)
- **Назначение:** Мобильное приложение проверяет статус кнопки паники.
- **Поведение:**  
  Возвращает текущий `emergencyState` и параметры конфигурации `needLockApproval` и `lockApprovalTimeSecond`.
- **Аутентификация:** HMAC через `X-EmergencyId`, `X-Timestamp` и `X-Signature`.

### `/mobile/lock` (POST)
- **Назначение:** Мобильное приложение запрашивает блокировку устройства (пометку как украденное).
- **Поведение:**  
  - Если `needLockApproval = true`:  
    - Первый запрос записывает время ожидания блокировки и возвращает 201 с просьбой о подтверждении.
    - Последующий запрос в течение окна подтверждения устанавливает `emergencyState` в true.
  - Если `needLockApproval = false`:  
    - Немедленно устанавливает `emergencyState` в true.
- **Аутентификация:** HMAC через `X-EmergencyId`, `X-Timestamp` и `X-Signature`.

### `/mobile/unlock` (POST)
- **Назначение:** Мобильное приложение запрашивает разблокировку устройства (сброс тревоги).
- **Поведение:**  
  - Аналогично `/mobile/lock`, при включенном `needLockApproval` требуется двухэтапное подтверждение.
  - Также проверяется флаг `userCanUnlock`.
- **Аутентификация:** HMAC, как выше.

### `/admin/register` (POST)
- **Назначение:** Администратор регистрирует новое устройство (если `needRegistrationApproval = true`).
- **Поведение:**  
  Создаёт новую запись устройства со случайными данными и возвращает `deviceId`.
- **Аутентификация:** Требуется заголовок `X-Admin-Token`, совпадающий с токеном из конфигурации.

### `/admin/unlock` (POST)
- **Назначение:** Администратор разблокирует устройство, сбрасывая тревожный режим.
- **Поведение:**  
  Принимает либо `deviceId`, либо `emergencyId` (приоритет у `emergencyId`), и сбрасывает `emergencyState`.
- **Аутентификация:** Требуется `X-Admin-Token`.

---

## Соображения безопасности

Система использует HMAC-аутентификацию для проверки целостности и подлинности запросов. Каждый запрос должен содержать:
- **X-DeviceId / X-EmergencyId:** Уникальный идентификатор устройства.
- **X-Timestamp:** Временная метка Unix (в виде строки) для предотвращения атак повторов.
- **X-Signature:** Подпись HMAC-SHA256, вычисленная над временной меткой с использованием токена устройства как ключа.

Сервер проверяет временную метку относительно настраиваемого временного окна (`hmacWindow`), чтобы предотвратить атаки повторов. Использование сильных, случайно сгенерированных токенов (256-битных) делает перебор HMAC-секрета вычислительно невозможным.

Проанализированы потенциальные уязвимости:
- **Атаки повторов:** Смягчаются с помощью временной метки и проверки окна времени.
- **Подбор токена:** Токены длиной 256 бит считаются безопасными.
- **Атаки "человек посередине":** Вся передача должна происходить по HTTPS с проверкой сертификатов.
- **Несанкционированный доступ администратора:** Защищается с помощью сильного случайного `adminToken`.

---

## Запуск сервера

1. **Установите зависимости:**  
   Убедитесь, что установлен Python 3.8+, и выполните установку:
   ```bash
   pip install fastapi uvicorn
   ```

2. **Настройте сервер:**  
   Создайте файл `server.conf` с нужными настройками (см. пример выше).

3. **Инициализируйте базу данных:**  
   Сервер автоматически создаёт `devices.db` и необходимую таблицу, если её нет.

4. **Запустите сервер:**  
   Запустите сервер с помощью Uvicorn:
   ```bash
   uvicorn backend:app --host 0.0.0.0 --port 8000
   ```

5. **Рекомендации для продакшена:**  
   Используйте менеджер процессов (например, Gunicorn с воркерами Uvicorn) и убедитесь, что HTTPS правильно настроен.

---

## Заключение

Серверная часть CorePost предоставляет надёжный, защищённый HMAC API для управления токенами расшифровки устройств и обработки запросов блокировки/тревоги. Она интегрируется с клиентскими устройствами, мобильными приложениями и административными инструментами, обеспечивая модель безопасности Zero Trust на уровне до загрузки ОС. Модульный дизайн позволяет дальнейшую настройку и масштабирование в соответствии с корпоративной политикой безопасности.

Для дополнительных вопросов или вкладов, обратитесь к репозиторию проекта.

## 🇬🇧 Overview

**CorePost** is a modular, open‐source security system designed to protect corporate devices from unauthorized access, data leaks, and theft. The server backend is a central component of the CorePost solution and is responsible for:

- **Device registration and token management**: Issuing secure tokens for disk decryption.
- **Panic management**: Enabling remote marking of devices as “stolen” via a panic API.
- **Status monitoring**: Allowing devices and mobile applications to check their current security status.
- **Administration**: Letting administrators unlock or register devices via a secure admin interface.

This backend is built using **Python**, **FastAPI**, and **SQLite**.

---

## Technical Details

### Architecture

The backend server exposes a REST API with the following key endpoints:
- `/client/register`
- `/client/AmIOk`
- `/client/decrypt`
- `/mobile/check`
- `/mobile/lock`
- `/mobile/unlock`
- `/admin/register`
- `/admin/unlock`

It uses HMAC-based authentication to protect sensitive endpoints. Clients (both devices and mobile apps) must include specific headers (e.g., `X-DeviceId`, `X-Timestamp`, `X-Signature`) with each request. The HMAC signature is computed using a shared secret (the device token) and the request timestamp to guard against replay attacks.

### Database Schema

The SQLite database (`devices.db`) contains a table named `devices` with the following columns:

| Column Name      | Type      | Description |
|------------------|-----------|-------------|
| `deviceId`       | TEXT      | Unique alphanumeric device identifier (primary key). |
| `emergencyId`    | TEXT      | Random hash used for panic (emergency) operations. |
| `emergencyState` | INTEGER   | Boolean flag (0 or 1) indicating whether the device is in panic mode. |
| `token`          | TEXT      | Secure random token used for decryption and HMAC authentication. Recommended length is 64 hex characters (256 bits). |
| `lastSeen`       | DATETIME  | Timestamp of the last successful heartbeat from the device. |
| `hwid`           | TEXT      | (Optional) Hardware identifier if required by configuration. |
| `pendingLockTime`| DATETIME  | Timestamp for pending lock requests when approval is required. |
| `userCanUnlock`  | INTEGER   | Boolean flag (1 or 0) indicating if the device is allowed to be unlocked remotely. |

The database is automatically initialized if it does not exist when the server starts.

---

## Security Considerations

### HMAC Authentication
- **Replay Protection:** Each request must include a timestamp (`X-Timestamp`) and a HMAC signature (`X-Signature`). The server verifies that the timestamp is within a configurable time window (default 5 seconds) to prevent replay attacks.
- **Token Strength:** The device token is generated as a 64-character hexadecimal string (256 bits of entropy), making brute-force attacks infeasible.
- **Device Binding:** Optionally, a hardware ID (`hwid`) can be required during registration, adding an extra factor to the device identity.
- **Transport Security:** All endpoints must be accessed over HTTPS. Certificates are managed on the server side, and mobile/desktop clients are expected to validate these certificates.

### Endpoint-Specific Security
- **Registration Endpoint (`/client/register`):**  
  If `needRegistrationApproval` is enabled, the device must pre-register (its `deviceId` must already exist in the database) and optionally provide its HWID. Otherwise, a new device record is created automatically.
- **Heartbeat Endpoint (`/client/AmIOk`):**  
  The device must authenticate and update its `lastSeen` timestamp. If the device is marked as stolen (`emergencyState = 1`), the request is rejected.
- **Decryption Endpoint (`/client/decrypt`):**  
  Only returns the decryption token in plain text if the device is not marked as stolen.
- **Mobile Endpoints (`/mobile/check`, `/mobile/lock`, `/mobile/unlock`):**  
  These endpoints use the `emergencyId` for authentication and manage the panic state. When `needLockApproval` is enabled, a two-step confirmation process is enforced to prevent accidental lock/unlock.
- **Admin Endpoints (`/admin/register`, `/admin/unlock`):**  
  Protected by a secret admin token provided in the header. These endpoints allow an administrator to register new devices (for approval) or unlock a device.

---

## Running the Server

### Prerequisites
- Python 3.8+ installed
- Dependencies installed (see `requirements.txt` if provided or install via pip)
- SQLite3 installed (usually included in standard Linux distributions)
- FastAPI and Uvicorn (`pip install fastapi uvicorn`)

### How to Run
1. **Configuration:**  
   Create a configuration file `server.conf` in the same directory as the server. A sample configuration is shown below.

2. **Database Initialization:**  
   The server code automatically initializes the SQLite database (`devices.db`) and creates the `devices` table if it does not exist.

3. **Starting the Server:**  
   Run the backend server using:
   ```bash
   uvicorn backend:app --host 0.0.0.0 --port 8000
   ```

4. **Production Considerations:**  
   - Use a process manager (like `gunicorn` with Uvicorn workers) for production.
   - Secure the admin token and ensure that all communications use HTTPS.

---

## Sample Configuration File (`server.conf`)

```ini
[server]
needRegistrationApproval = false
needHWID = false
needLockApproval = true
lockApprovalTimeSecond = 30
adminToken = supersecretadmin

[security]
hmacWindow = 5
```

---

## Endpoint Documentation

### `/client/register` (POST)
- **Purpose:** Register a new device.
- **Behavior:**
  - If `needRegistrationApproval` is `true`, the request must include a pre-registered `deviceId` (and optionally `hwid` if `needHWID` is enabled). If not found, returns an error.
  - If `needRegistrationApproval` is `false`, a new record is created with random values:
    - `deviceId`: 16 hex characters (8 bytes)
    - `emergencyId`: 16 hex characters (8 bytes)
    - `token`: 64 hex characters (32 bytes)
    - `emergencyState`: set to 0
    - `lastSeen`: current timestamp
- **Response:** JSON with `deviceId`, `emergencyId`, and `token`.

### `/client/AmIOk` (POST)
- **Purpose:** Heartbeat endpoint for devices.
- **Behavior:**  
  Updates `lastSeen` timestamp. Returns 200 OK if `emergencyState` is false; otherwise, returns a 403 error indicating the device is marked as stolen.
- **Authentication:** HMAC using headers `X-DeviceId`, `X-Timestamp`, and `X-Signature`.

### `/client/decrypt` (GET)
- **Purpose:** Retrieve the decryption token.
- **Behavior:**  
  Returns the device’s `token` as plain text if `emergencyState` is false; otherwise, returns a 403 error.
- **Authentication:** HMAC as above.

### `/mobile/check` (GET)
- **Purpose:** Mobile app checks the device's emergency (panic) status.
- **Behavior:**  
  Returns the current `emergencyState`, and configuration parameters `needLockApproval` and `lockApprovalTimeSecond`.
- **Authentication:** HMAC using `X-EmergencyId`, `X-Timestamp`, and `X-Signature`.

### `/mobile/lock` (POST)
- **Purpose:** Mobile app requests device lockdown (mark as stolen).
- **Behavior:**  
  - If `needLockApproval` is `true`:  
    - On first request, records a pending lock time and returns 201 asking for confirmation.
    - On a subsequent request within the approval window, sets `emergencyState` to true.
  - If `needLockApproval` is `false`:  
    - Immediately sets `emergencyState` to true.
- **Authentication:** HMAC using `X-EmergencyId`, `X-Timestamp`, and `X-Signature`.

### `/mobile/unlock` (POST)
- **Purpose:** Mobile app requests device unlock (clear emergency state).
- **Behavior:**  
  - Similar to `/mobile/lock`, if `needLockApproval` is enabled, requires a two-step confirmation.
  - Also checks if the device is allowed to unlock (`userCanUnlock` flag).
- **Authentication:** HMAC as above.

### `/admin/register` (POST)
- **Purpose:** Admin registers a new device (for scenarios with `needRegistrationApproval = true`).
- **Behavior:**  
  Creates a new device record with random data and returns the `deviceId`.
- **Authentication:** Requires header `X-Admin-Token` matching the configured admin token.

### `/admin/unlock` (POST)
- **Purpose:** Admin unlocks a device by clearing its emergency state.
- **Behavior:**  
  Accepts either `deviceId` or `emergencyId` (with `emergencyId` having priority) and clears `emergencyState`.
- **Authentication:** Requires `X-Admin-Token`.

---

## Security Considerations

The system employs HMAC-based authentication to verify the integrity and authenticity of requests. Each request must include:
- **X-DeviceId / X-EmergencyId:** Unique identifier of the device.
- **X-Timestamp:** Unix timestamp (as a string) to prevent replay attacks.
- **X-Signature:** HMAC-SHA256 signature computed over the timestamp using the device’s token as the key.

The server validates the timestamp against a configurable time window (`hmacWindow`) to thwart replay attacks. The use of strong, randomly generated tokens (256-bit) ensures that brute-forcing the HMAC secret is computationally infeasible.

Potential vulnerabilities have been analyzed:
- **Replay attacks:** Mitigated by using a timestamp and time-window validation.
- **Token brute-forcing:** Tokens are 256-bit (64 hex characters), which is secure.
- **Man-in-the-middle attacks:** All communication should occur over HTTPS with proper certificate validation.
- **Unauthorized admin access:** Protected via a strong, random `adminToken`.

---

## Running the Server

1. **Install Dependencies:**  
   Ensure Python 3.8+ is installed and install dependencies:
   ```bash
   pip install fastapi uvicorn
   ```

2. **Configure the Server:**  
   Create a file named `server.conf` with the desired settings (see sample above).

3. **Initialize the Database:**  
   The server automatically creates `devices.db` and the required table if it does not exist.

4. **Start the Server:**  
   Run the server using Uvicorn:
   ```bash
   uvicorn backend:app --host 0.0.0.0 --port 8000
   ```

5. **Production Considerations:**  
   Use a process manager (e.g., Gunicorn with Uvicorn workers) and ensure that HTTPS termination is correctly configured.

---

## Conclusion

The CorePost backend server provides a robust, HMAC-secured API for managing device decryption tokens and handling panic/lock requests. It integrates with client devices, mobile applications, and administrative tools to enforce a Zero Trust security model at the pre-boot level. The modular design allows for further customization and scaling according to corporate security policies.

For further questions or contributions, please refer to the project repository.

