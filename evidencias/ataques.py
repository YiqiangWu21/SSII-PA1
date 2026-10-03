"""
ataques.py - Genera tráfico legítimo y tráfico de ataque contra el servidor SecBank.

Uso:
    python evidencias/ataques.py [url_base]        (por defecto http://127.0.0.1:8000)

Requiere la variable de entorno SECBANK_HMAC_KEY (la misma que usa el servidor).
Opcionalmente SECBANK_USER y SECBANK_PASS (por defecto, el usuario de prueba
precargado: cliente_prueba / PasswordSegura123).

Flujo:
  0. Login firmado (HMAC + nonce + timestamp) para obtener el token de sesión.
  1. Transferencia legítima con el token: debe devolver 2xx.
  2-6. Ataques MitM y Replay sobre /transfer: deben ser rechazados por el middleware.

Cada petición lleva una cabecera X-Escenario con su nombre, solo para localizarla
en Wireshark (no forma parte de la firma).

Cómo se distingue un rechazo del middleware: sus errores tienen la forma
{"detail": {"error": "..."}}, mientras que la lógica de negocio devuelve
{"detail": "texto"}.
"""
import hashlib
import hmac
import http.client
import json
import os
import sys
import time
import uuid
from urllib.parse import urlparse

sys.stdout.reconfigure(encoding="utf-8")

BASE = sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:8000"
USUARIO = os.environ.get("SECBANK_USER", "cliente_prueba")
CLAVE_USUARIO = os.environ.get("SECBANK_PASS", "PasswordSegura123")

try:
    KEY = bytes.fromhex(os.environ["SECBANK_HMAC_KEY"])
except (KeyError, ValueError):
    print("Define SECBANK_HMAC_KEY (64 caracteres hexadecimales) en esta terminal.")
    sys.exit(2)


# ----------------------------------------------------------- construcción del paquete

def canonico(payload: dict) -> bytes:
    """Mismo JSON compacto y ordenado que usa el cliente: estos bytes se firman y se envían."""
    return json.dumps(payload, separators=(",", ":"), sort_keys=True,
                      ensure_ascii=False, allow_nan=False).encode("utf-8")


def firmar(body: bytes, nonce: str, ts: int) -> str:
    """HMAC-SHA256( timestamp \\n nonce \\n body )."""
    msg = f"{ts}\n{nonce}\n".encode("utf-8") + body
    return hmac.new(KEY, msg, hashlib.sha256).hexdigest()


def paquete(payload, token=None, ts=None, nonce=None):
    """Devuelve (body, headers) de una petición bien firmada."""
    ts = int(time.time()) if ts is None else ts
    nonce = str(uuid.uuid4()) if nonce is None else nonce
    body = canonico(payload)
    headers = {
        "Content-Type": "application/json",
        "X-Signature": firmar(body, nonce, ts),
        "X-Nonce": nonce,
        "X-Timestamp": str(ts),
    }
    if token:
        headers["Authorization"] = f"Bearer {token}"
    return body, headers


def transferencia(ts, importe=1250.75):
    return {
        "tx_id": str(uuid.uuid4()),
        "origin_account": "ES1234567890123456789012",
        "destination_account": "ES9876543210987654321098",
        "amount": importe,
        "currency": "EUR",
        "timestamp": ts,
    }


# ------------------------------------------------------------------------ envío

def enviar(path, body, headers, escenario):
    """Envía por HTTP en texto plano (sin TLS). Devuelve (status, mensaje, es_middleware, json)."""
    destino = urlparse(BASE)
    conexion = http.client.HTTPConnection(destino.hostname, destino.port, timeout=5)
    try:
        conexion.request("POST", path, body=body, headers={**headers, "X-Escenario": escenario})
        respuesta = conexion.getresponse()
        texto = respuesta.read().decode("utf-8", "replace")
        status = respuesta.status
    finally:
        conexion.close()
    try:
        datos = json.loads(texto)
    except ValueError:
        datos = None
    detalle = datos.get("detail", texto) if isinstance(datos, dict) else texto
    if isinstance(detalle, dict):
        return status, detalle.get("error", str(detalle)), True, datos
    return status, str(detalle), False, datos


resultados = []


def caso(numero, nombre, escenario, body, headers, esperado_status=None, esperado_msg=None):
    """Sin esperado_msg: la petición debe ser ACEPTADA (2xx). Con él: rechazada por el middleware."""
    time.sleep(0.2)  # separa las peticiones para que la captura sea fácil de leer
    status, mensaje, es_middleware, datos = enviar("/transfer", body, headers, escenario)
    if esperado_msg is None:
        ok = 200 <= status < 300
        esperado = "2xx (transferencia registrada)"
        respuesta = f"{status} {json.dumps(datos, ensure_ascii=False) if datos else mensaje}"
    else:
        ok = es_middleware and status == esperado_status and mensaje == esperado_msg
        esperado = f"{esperado_status} {esperado_msg}"
        respuesta = f"{status} {mensaje}"
    resultados.append(ok)
    print(f"[{'OK' if ok else 'FALLO'}] {numero}. {nombre}")
    print(f"        respuesta: {respuesta}")
    if not ok:
        print(f"        esperado : {esperado}")


# ---------------------------------------------------------------------- escenarios

print(f"Servidor: {BASE}\n")

# 0. Login firmado: obtiene el token de sesión
body_login, headers_login = paquete({"username": USUARIO, "password": CLAVE_USUARIO})
status, mensaje, es_mw, datos = enviar("/auth/login", body_login, headers_login, "00_login")
token = datos.get("access_token") if isinstance(datos, dict) else None
print(f"[{'OK' if token else 'FALLO'}] 0. Login de {USUARIO}")
print(f"        respuesta: {status} {mensaje if not token else 'token de sesión recibido'}")
if not token:
    print("\nSin token no se puede continuar. Comprueba el usuario (SECBANK_USER / SECBANK_PASS),")
    print("que la base de datos tiene ese usuario, y que la clave HMAC coincide con la del servidor.")
    sys.exit(1)
resultados.append(True)
print()

# 1. Transferencia legítima (se guarda el paquete: el atacante "lo captura" para el replay)
ts1 = int(time.time())
body_ok, headers_ok = paquete(transferencia(ts1), token, ts=ts1)
caso(1, "Transferencia legítima", "01_legitima", body_ok, headers_ok)

# 2. MitM: el atacante cambia el importe en tránsito, pero no puede recalcular la firma
ts2 = int(time.time())
body_mitm, headers_mitm = paquete(transferencia(ts2, 1250.75), token, ts=ts2)
body_alterado = body_mitm.replace(b"1250.75", b"9999.99")
caso(2, "MitM: cuerpo alterado en tránsito", "02_mitm_cuerpo",
     body_alterado, headers_mitm, 401, "Firma inválida.")

# 3. MitM: el atacante modifica la propia firma
ts3 = int(time.time())
body3, headers3 = paquete(transferencia(ts3), token, ts=ts3)
f = headers3["X-Signature"]
headers3["X-Signature"] = f[:-1] + ("0" if f[-1] != "0" else "1")
caso(3, "MitM: firma alterada", "03_mitm_firma", body3, headers3, 401, "Firma inválida.")

# 4. REPLAY: se reenvía EXACTAMENTE el paquete legítimo capturado en el caso 1
caso(4, "Replay: mismo paquete reenviado", "04_replay", body_ok, headers_ok,
     401, "Nonce ya utilizado.")

# 5. REPLAY tardío: paquete con firma correcta pero de hace 2 minutos
ts5 = int(time.time()) - 120
body5, headers5 = paquete(transferencia(ts5), token, ts=ts5)
caso(5, "Replay: timestamp caducado (hace 120 s)", "05_replay_timestamp",
     body5, headers5, 401, "La solicitud ha expirado.")

# 6. Nonce en mayúsculas (intento de burlar la tabla de nonces del caso 1)
ts6 = int(time.time())
body6, headers6 = paquete(transferencia(ts6), token, ts=ts6, nonce=headers_ok["X-Nonce"].upper())
caso(6, "Replay: nonce en mayúsculas", "06_nonce_mayusculas",
     body6, headers6, 400, "Formato de nonce inválido.")

# ------------------------------------------------------------------------ resumen
print(f"\nResultado: {sum(resultados)}/{len(resultados)} escenarios como se esperaba")
sys.exit(0 if all(resultados) else 1)
