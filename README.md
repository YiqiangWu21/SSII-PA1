# SecBank — IntegriDos (PAI-1)

Verificador de integridad de mensajes para transferencias bancarias sobre una red pública **sin TLS/HTTPS**.
Proyecto de la asignatura *Seguridad en Sistemas Informáticos e Internet* (Universidad de Sevilla).

> Proyecto con fines educativos. Toda la seguridad se implementa en la **capa de aplicación**; el uso de
> TLS/HTTPS/SSL está prohibido por el enunciado y el cliente lo rechaza expresamente.

## 1. Qué hace

SecBank es un sistema cliente-servidor en el que los usuarios se registran, inician sesión y envían órdenes
de transferencia. Cada petición va firmada para que el servidor pueda detectar cualquier manipulación en tránsito.

| Amenaza | Defensa implementada |
|---|---|
| Man-in-the-Middle (alterar el mensaje) | Firma **HMAC-SHA256** sobre `timestamp \n nonce \n cuerpo` |
| Replay (reenviar un paquete capturado) | **Nonce** UUIDv4 de un solo uso + **timestamp** con ventana de ±30 s |
| Robo / fuerza bruta de credenciales | **Argon2id** con salt único por usuario + bloqueo temporal tras 5 fallos |
| Timing side-channel | Comparación de firmas con `secrets.compare_digest` (tiempo constante) |
| Claves débiles | Clave de ≥ 256 bits desde variable de entorno; el servidor no arranca si es corta o de ceros |

## 2. Arquitectura

Transporte elegido: **Opción B — API REST sobre HTTP/1.1 en texto plano** (FastAPI en el servidor, `urllib` en el cliente).

```
┌────────────────────┐   HTTP plano (red pública)   ┌──────────────────────────────────────┐
│ Cliente (client/)  │ ───────────────────────────► │ Servidor (server/)                   │
│  ui.py  (CLI)      │   POST + X-Signature         │  security/middleware.py  (capa 3)    │
│  network.py        │        X-Nonce               │    cabeceras → timestamp → nonce     │
│  security.py       │        X-Timestamp           │    → HMAC → registro de nonce        │
│                    │        Authorization: Bearer │  routes/  auth.py, transfer.py       │
└────────────────────┘                              │  database/business_logic.py (capa 2) │
                                                    │  SQLite (users, transactions, nonces)│
                                                    └──────────────────────────────────────┘
```

### Estructura del repositorio

```
.
├── client/
│   ├── ui.py            # CLI interactiva y construcción de transferencias
│   ├── network.py       # Cliente REST: firma, cabeceras, sesión
│   ├── security.py      # SecurityManager: clave, nonce, timestamp, HMAC
│   ├── pytest.ini
│   └── tests/           # Tests unitarios + integración cliente↔servidor
├── server/
│   ├── main.py          # App FastAPI (middleware de seguridad global)
│   ├── routes/          # /auth/register, /auth/login, /auth/logout, /transfer
│   ├── security/        # crypto.py (HMAC), middleware.py, logging_config.py
│   ├── database/        # models.py, database.py, business_logic.py
│   ├── tests/           # Tests del servidor
│   └── pytest.ini
├── evidencias/          # Scripts y resultados (pcap, logs, tiempos, figuras)
├── requirements.txt
├── .env.example
└── README.md
```

## 3. Protocolo

Cada petición `POST` lleva el cuerpo JSON y tres cabeceras de control:

| Cabecera | Contenido |
|---|---|
| `X-Timestamp` | Segundos Unix en el momento de enviar |
| `X-Nonce` | UUIDv4 aleatorio **en minúsculas** |
| `X-Signature` | `HMAC-SHA256(clave, f"{timestamp}\n{nonce}\n" + cuerpo)` en hexadecimal |

El **cuerpo canónico** que se firma y se envía es el mismo byte a byte:
`json.dumps(payload, separators=(",", ":"), sort_keys=True, ensure_ascii=False)` en UTF-8.

El servidor valida, de la comprobación más barata a la más cara, y rechaza en el primer fallo:

1. Cabeceras presentes (`400`).
2. Timestamp dentro de ±30 s (`401`).
3. Formato UUIDv4 en minúsculas del nonce (`400`).
4. Firma HMAC en tiempo constante (`401`).
5. Nonce no usado antes: inserción atómica en BD con clave primaria; purga de nonces con más de 60 s (`401`).

Después se comprueba el token de sesión (`Authorization: Bearer …`) y se procesa la lógica de negocio.
Cada aceptación y rechazo se registra en `server/logs/security.log` (auditoría).

### Transacción

```json
{
  "tx_id": "UUIDv4",
  "origin_account": "ES1234567890123456789012",
  "destination_account": "ES9876543210987654321098",
  "amount": 1500.50,
  "currency": "EUR",
  "timestamp": 1741690000
}
```

El `timestamp` del cuerpo se fija **justo antes de enviar** y coincide con `X-Timestamp`.

### Endpoints

| Método y ruta | Descripción | Respuestas |
|---|---|---|
| `POST /auth/register` | Alta de usuario (contraseña ≥ 8 caracteres) | 200 · 400 · 409 usuario duplicado |
| `POST /auth/login` | Devuelve token de sesión opaco | 200 · 401 · 429 cuenta bloqueada |
| `POST /auth/logout` | Revoca el token | 200 · 401 |
| `POST /transfer` | Registra una transferencia (requiere token) | 200 · 400 · 401 · 409 `tx_id` duplicado |

Todos exigen las tres cabeceras de seguridad, también login y registro.

## 4. Requisitos previos

- Python 3.10 o superior.
- (Opcional, para evidencias) Wireshark o `tcpdump`, y `matplotlib` para generar la gráfica de tiempos.

## 5. Instalación

```bash
git clone <url-del-repositorio>
cd SSII-PA1

python -m venv venv
# Linux / macOS
source venv/bin/activate
# Windows (PowerShell)
venv\Scripts\Activate.ps1

pip install -r requirements.txt
```

### Clave HMAC compartida

Cliente y servidor leen la clave de la variable de entorno `SECBANK_HMAC_KEY` (64 caracteres hexadecimales = 256 bits).
**Nunca** va en el código.

```bash
cp .env.example .env              # Windows: copy .env.example .env
python -c "import secrets; print(secrets.token_hex(32))"
# pega el resultado en .env:  SECBANK_HMAC_KEY=<valor>
```

- El **cliente** carga `.env` automáticamente (`python-dotenv`).
- El **servidor** lee solo variables de entorno: pásale el fichero con `--env-file` (ver abajo) o exporta la variable
  en la terminal (`export SECBANK_HMAC_KEY=...` en Linux/macOS; `$env:SECBANK_HMAC_KEY="..."` en PowerShell).

## 6. Ejecución

### Servidor (terminal 1)

```bash
cd server
python -m uvicorn main:app --host 127.0.0.1 --port 8000 --env-file ../.env
```

Al arrancar crea la base de datos `secbank.db`, activa el log de seguridad y precarga el usuario de pruebas
**`cliente_prueba` / `PasswordSegura123`**. Si falta la clave o es insegura, el servidor se niega a arrancar.

### Cliente (terminal 2)

```bash
cd client
python ui.py
```

Menú: `1` registrar · `2` iniciar sesión · `3` enviar transferencia · `4` cerrar sesión · `5` salir.
Para apuntar a otro servidor: `SECBANK_URL=http://IP:PUERTO` (solo `http://`).

Prueba rápida: opción 2 con el usuario de pruebas → opción 3 con
origen `ES1234567890123456789012`, destino `ES9876543210987654321098` e importe `100`.

## 7. Cómo comprobar que funciona

### 7.1 Tests automáticos

Se ejecutan por separado porque cliente y servidor tienen cada uno un módulo `security`.

```bash
# Servidor (34 tests, BD en memoria, no necesita servidor arrancado)
cd server && python -m pytest -q

# Cliente (unitarios + integración con servidor real, BD temporal)
cd client && python -m pytest -q
```

Los tests de integración (`client/tests/test_integration.py`) arrancan su propio `uvicorn` en un puerto libre con BD
y clave temporales, así que no interfieren con tu servidor ni con tu `secbank.db`. Comprueban que el cliente firma
exactamente como el servidor verifica y que MitM, replay, timestamp caducado, nonce en mayúsculas, clave distinta y
fuerza bruta se rechazan. Para ejecutar solo los unitarios: `python -m pytest -q -m "not integration"`.

### 7.2 Ataques de demostración y evidencias

Con el servidor arrancado y la misma clave en el entorno:

```bash
python evidencias/ataques.py                  # 7 escenarios: legítimo + MitM + replay
python evidencias/analisis_tiempos.py         # == vs compare_digest → tiempos.csv / tiempos.png
```

`ataques.py` debe terminar con «7/7 escenarios como se esperaba». Para la captura de tráfico (`.pcap`):

1. Abre Wireshark en la interfaz **loopback** (Linux: `lo`; Windows: *Npcap Loopback Adapter*) con el filtro `tcp.port == 8000`.
2. Lanza `ataques.py` y detén la captura.
3. Guárdala como `evidencias/captura_ataques.pcap`. Las peticiones llevan la cabecera `X-Escenario`
   para localizarlas fácilmente (`http.request.method == "POST"`).

Con `tcpdump`: `sudo tcpdump -i lo -w evidencias/captura_ataques.pcap tcp port 8000`.

### 7.3 Contenido de `evidencias/`

| Fichero | Qué demuestra |
|---|---|
| `captura_ataques.pcap` | Tramas firmadas en claro sobre el canal no seguro |
| `ataques_salida.txt` | Resultado de cada escenario de ataque |
| `fig3_mitm.png`, `fig4_replay.png` | Rechazo de MitM y de Replay |
| `security.log` | Auditoría de aceptaciones y rechazos del servidor |
| `tiempos.csv`, `tiempos.png`, `tiempos_salida.txt` | Análisis de canal lateral de tiempo |

## 8. Trazabilidad de requisitos

| Requisito del enunciado | Implementación |
|---|---|
| Registro, usuarios de prueba, sin duplicados | `server/database/business_logic.py::register_user`, `server/main.py::initialize_default_user` |
| Sesiones activas y logout | `business_logic.py` (`verify_login`, `validate_and_revoke_token`), `routes/auth.py` |
| Transacciones JSON verificadas | `routes/transfer.py`, `security/middleware.py` |
| **RS1** Derivación robusta + salt único | `business_logic.py` (Argon2id con `argon2-cffi`; la sal va incluida en el hash) |
| **RS1b** Protección contra fuerza bruta | `MAX_FAILED_ATTEMPTS = 5`, bloqueo de 15 min (`business_logic.py`) |
| **RS2** HMAC-SHA256 y clave ≥ 256 bits | `server/security/crypto.py`, `client/security.py` |
| **RS3** Nonce, timestamp y tabla de nonces | `security/middleware.py`, modelo `Nonce` en `database/models.py` |
| **RS4** Comparación en tiempo constante | `crypto.py::verify_hmac` (`secrets.compare_digest`) |
| Sin TLS/HTTPS | `client/network.py` (solo `http://`); servidor sin certificados |
| Evidencias `.pcap` y análisis de tiempo | `evidencias/` |

## 9. Uso de IA

Se empleó IA generativa como asistente de programación, revisión y documentación. Todo el código se revisó y validó
manualmente con los tests automáticos y los escenarios de ataque descritos arriba, y se comprobó que no introduce
TLS, funciones hash obsoletas (MD5/SHA-1) ni comparadores vulnerables a timing. El detalle de tareas y validación
está en el apartado correspondiente de la memoria.

## 10. Limitaciones conocidas

- La clave HMAC es compartida y global (permitido por el enunciado); no hay clave por sesión.
- La firma cubre timestamp, nonce y cuerpo, pero **no** la ruta ni la cabecera `Authorization`.
- El servidor no comprueba que `origin_account` pertenezca al usuario autenticado.
- El token de sesión no caduca (solo se revoca con logout) y hay un único token activo por usuario.
- La respuesta `429` de login revela que el usuario existe.

## 11. Solución de problemas

| Síntoma | Causa y solución |
|---|---|
| `RuntimeError: Falta la variable de entorno SECBANK_HMAC_KEY` | Falta la clave. Revisa `.env` o exporta la variable. |
| `401 Firma inválida` en todo | Cliente y servidor usan claves distintas. |
| `401 La solicitud ha expirado` | Relojes desincronizados más de 30 s entre cliente y servidor. |
| `ModuleNotFoundError: security` / `database` | Ejecuta desde `server/` (uvicorn, pytest) o `client/` (ui.py, pytest). |
| `429 Cuenta bloqueada` | 5 fallos seguidos; espera 15 min o borra `server/secbank.db` en desarrollo. |
| Puerto 8000 ocupado | Usa `--port 8001` y `SECBANK_URL=http://127.0.0.1:8001`. |