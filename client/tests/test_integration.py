"""
Pruebas de integración cliente <-> servidor real.

Arrancan uvicorn con una BD temporal y una clave de prueba, y comprueban que el
cliente firma EXACTAMENTE como el servidor verifica (el punto más frágil al
fusionar las ramas) y que los ataques del enunciado se rechazan.

Se saltan solas si no se encuentra la carpeta server/ o uvicorn.
"""
import json
import os
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.request
import uuid
from pathlib import Path

import pytest

from network import SecBankClient
from security import SecurityManager

pytestmark = pytest.mark.integration

SERVER_DIR = Path(__file__).resolve().parents[2] / "server"
KEY_HEX = "ab" * 32
ORIGEN = "ES1234567890123456789012"
DESTINO = "ES9876543210987654321098"


def _free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@pytest.fixture(scope="module")
def server(tmp_path_factory):
    if not (SERVER_DIR / "main.py").exists():
        pytest.skip("No se encuentra server/main.py")
    try:
        import uvicorn  # noqa: F401
    except ImportError:
        pytest.skip("uvicorn no instalado")

    workdir = tmp_path_factory.mktemp("srv")  # la BD sqlite se crea en el cwd
    port = _free_port()
    env = {**os.environ, "SECBANK_HMAC_KEY": KEY_HEX, "PYTHONPATH": str(SERVER_DIR)}
    proc = subprocess.Popen(
        [sys.executable, "-m", "uvicorn", "main:app", "--port", str(port), "--log-level", "warning"],
        cwd=workdir, env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
    )
    url = f"http://127.0.0.1:{port}"
    for _ in range(60):
        if proc.poll() is not None:
            pytest.fail("El servidor no arrancó:\n" + proc.stdout.read().decode(errors="replace"))
        try:
            socket.create_connection(("127.0.0.1", port), timeout=0.5).close()
            break
        except OSError:
            time.sleep(0.25)
    else:
        proc.kill()
        pytest.fail("Timeout esperando al servidor")
    yield url
    proc.terminate()
    try:
        proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        proc.kill()


@pytest.fixture
def sec():
    return SecurityManager(bytes.fromhex(KEY_HEX))


@pytest.fixture
def client(server, sec):
    return SecBankClient(sec, base_url=server)


def _tx(amount=100.0):
    return {"tx_id": str(uuid.uuid4()), "origin_account": ORIGEN, "destination_account": DESTINO,
            "amount": amount, "currency": "EUR"}


def _raw_post(url, path, payload, sec, token=None, body=None, nonce=None, ts=None, sig=None):
    """POST manual para simular a un atacante."""
    body_ok = sec.canonical_body(payload)
    nonce = nonce or sec.generate_nonce()
    ts = ts or sec.get_timestamp()
    headers = {"Content-Type": "application/json", "X-Nonce": nonce, "X-Timestamp": str(ts),
               "X-Signature": sig or sec.generate_signature(body_ok, nonce, ts)}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    req = urllib.request.Request(url + path, data=body or body_ok, headers=headers, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=5) as r:
            return r.status
    except urllib.error.HTTPError as e:
        return e.code


# ---------- Flujo legítimo ----------
def test_flujo_completo(client):
    user = "u_" + uuid.uuid4().hex[:8]
    assert client.register(user, "ClaveSegura99")
    assert not client.register(user, "ClaveSegura99") and "existe" in client.last_error
    assert client.login(user, "ClaveSegura99")
    tx = _tx()
    res = client.send_transfer(tx)
    assert res["success"] and res["data"]["status"] == "registrada"
    dup = client.send_transfer(tx)  # mismo tx_id, nonce nuevo
    assert not dup["success"] and dup["status"] == 409
    client.logout()
    assert client.session_token is None


def test_usuario_preregistrado(client):
    assert client.login("cliente_prueba", "PasswordSegura123")


def test_logout_invalida_el_token(client, server, sec):
    user = "u_" + uuid.uuid4().hex[:8]
    client.register(user, "ClaveSegura99")
    client.login(user, "ClaveSegura99")
    token = client.session_token
    client.logout()
    assert _raw_post(server, "/transfer", {**_tx(), "timestamp": sec.get_timestamp()}, sec, token=token) == 401


def test_login_incorrecto(client):
    assert not client.login("cliente_prueba", "otra_clave_mala")
    assert client.session_token is None


# ---------- Ataques ----------
@pytest.fixture
def token(client):
    client.login("cliente_prueba", "PasswordSegura123")
    return client.session_token


def _signed_tx(sec):
    return {**_tx(200), "timestamp": sec.get_timestamp()}


def test_mitm_cuerpo_alterado(server, sec, token):
    original = _signed_tx(sec)
    alterado = sec.canonical_body({**original, "amount": 2000})
    assert _raw_post(server, "/transfer", original, sec, token=token, body=alterado) == 401


def test_mitm_firma_alterada(server, sec, token):
    assert _raw_post(server, "/transfer", _signed_tx(sec), sec, token=token, sig="0" * 64) == 401


def test_replay_mismo_nonce(server, sec, token):
    tx = _signed_tx(sec)
    nonce = sec.generate_nonce()
    assert _raw_post(server, "/transfer", tx, sec, token=token, nonce=nonce) == 200
    assert _raw_post(server, "/transfer", tx, sec, token=token, nonce=nonce) == 401


def test_replay_timestamp_caducado(server, sec, token):
    viejo = sec.get_timestamp() - 120
    assert _raw_post(server, "/transfer", {**_tx(), "timestamp": viejo}, sec, token=token, ts=viejo) == 401


def test_nonce_en_mayusculas_rechazado(server, sec, token):
    assert _raw_post(server, "/transfer", _signed_tx(sec), sec, token=token,
                     nonce=str(uuid.uuid4()).upper()) == 400


def test_clave_distinta_firma_rechazada(server, token):
    intruso = SecurityManager(b"\x99" * 32)
    assert _raw_post(server, "/transfer", {**_tx(), "timestamp": intruso.get_timestamp()}, intruso, token=token) == 401


def test_bloqueo_por_fuerza_bruta(client):
    user = "u_" + uuid.uuid4().hex[:8]
    client.register(user, "ClaveSegura99")
    for _ in range(5):
        client.login(user, "mala_clave_1")
    assert not client.login(user, "ClaveSegura99")  # bloqueada aunque la clave sea correcta
    assert "bloqueada" in client.last_error.lower()
