"""
ataques.py - Genera tráfico legítimo y tráfico de ataque contra el servidor SecBank.

Uso:
    python ataques.py [url_base]        (por defecto http://127.0.0.1:8000)

Requiere la variable de entorno SECBANK_HMAC_KEY (la misma que usa el servidor).
Cada petición lleva una cabecera X-Escenario con su nombre, solo para poder
localizarla fácilmente en Wireshark (no forma parte de la firma).

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

BASE = sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:8000"
PATH = "/transfer"

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


def paquete(ts=None, nonce=None, importe=1250.75):
    """Devuelve (body, headers) de una transferencia legítima y bien firmada."""
    ts = int(time.time()) if ts is None else ts
    nonce = str(uuid.uuid4()) if nonce is None else nonce
    payload = {
        "tx_id": str(uuid.uuid4()),
        "origin_account": "ES1234567890123456789012",
        "destination_account": "ES9876543210987654321098",
        "amount": importe,
        "currency": "EUR",
        "timestamp": ts,
    }
    body = canonico(payload)
    headers = {
        "Content-Type": "application/json",
        "X-Signature": firmar(body, nonce, ts),
        "X-Nonce": nonce,
        "X-Timestamp": str(ts),
    }
    return body, headers


# ------------------------------------------------------------------------ envío

def enviar(body: bytes, headers: dict, escenario: str):
    """Envía por HTTP en texto plano (sin TLS) y devuelve (status, mensaje, es_middleware)."""
    destino = urlparse(BASE)
    conexion = http.client.HTTPConnection(destino.hostname, destino.port, timeout=5)
    try:
        conexion.request("POST", PATH, body=body, headers={**headers, "X-Escenario": escenario})
        respuesta = conexion.getresponse()
        texto = respuesta.read().decode("utf-8", "replace")
        status = respuesta.status
    finally:
        conexion.close()
    try:
        detalle = json.loads(texto).get("detail", texto)
    except ValueError:
        detalle = texto
    if isinstance(detalle, dict):
        return status, detalle.get("error", str(detalle)), True
    return status, str(detalle), False


resultados = []


def caso(numero, nombre, escenario, body, headers, esperado_status=None, esperado_msg=None):
    """esperado_msg=None significa: debe PASAR el middleware (no ser rechazado por él)."""
    time.sleep(0.2)  # separa las peticiones para que la captura sea fácil de leer
    status, mensaje, es_middleware = enviar(body, headers, escenario)
    if esperado_msg is None:
        ok = not es_middleware
        esperado = "pasa el middleware"
    else:
        ok = es_middleware and status == esperado_status and mensaje == esperado_msg
        esperado = f"{esperado_status} {esperado_msg}"
    resultados.append(ok)
    print(f"[{'OK' if ok else 'FALLO'}] {numero}. {nombre}")
    print(f"        respuesta: {status} {mensaje}")
    if not ok:
        print(f"        esperado : {esperado}")


# ---------------------------------------------------------------------- escenarios

print(f"Servidor: {BASE}{PATH}\n")

# 1. Petición legítima (se guarda el paquete: el atacante "lo captura" para el replay)
body_ok, headers_ok = paquete()
caso(1, "Petición legítima", "01_legitima", body_ok, headers_ok)

# 2. MitM: el atacante cambia el importe en tránsito, pero no puede recalcular la firma
body_mitm, headers_mitm = paquete(importe=1250.75)
body_alterado = body_mitm.replace(b"1250.75", b"9999.99")
caso(2, "MitM: cuerpo alterado en tránsito", "02_mitm_cuerpo",
     body_alterado, headers_mitm, 401, "Firma inválida.")

# 3. MitM: el atacante modifica la propia firma
body3, headers3 = paquete()
f = headers3["X-Signature"]
headers3["X-Signature"] = f[:-1] + ("0" if f[-1] != "0" else "1")
caso(3, "MitM: firma alterada", "03_mitm_firma", body3, headers3, 401, "Firma inválida.")

# 4. REPLAY: se reenvía EXACTAMENTE el paquete legítimo capturado en el caso 1
caso(4, "Replay: mismo paquete reenviado", "04_replay", body_ok, headers_ok,
     401, "Nonce ya utilizado.")

# 5. REPLAY tardío: paquete con firma correcta pero de hace 2 minutos
body5, headers5 = paquete(ts=int(time.time()) - 120)
caso(5, "Replay: timestamp caducado (hace 120 s)", "05_replay_timestamp",
     body5, headers5, 401, "La solicitud ha expirado.")

# 6. Nonce en mayúsculas (intento de burlar la tabla de nonces del caso 1)
body6, headers6 = paquete(nonce=headers_ok["X-Nonce"].upper())
caso(6, "Replay: nonce en mayúsculas", "06_nonce_mayusculas",
     body6, headers6, 400, "Formato de nonce inválido.")

# ------------------------------------------------------------------------ resumen
print(f"\nResultado: {sum(resultados)}/{len(resultados)} escenarios como se esperaba")
sys.exit(0 if all(resultados) else 1)
