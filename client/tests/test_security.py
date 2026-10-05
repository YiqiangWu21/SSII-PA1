import hashlib
import hmac
import json
import re
import uuid

import pytest

from security import SecurityManager, MIN_KEY_BYTES

UUID4_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$")


# ---------- Clave (RS2b) ----------
def test_rechaza_clave_corta():
    with pytest.raises(ValueError):
        SecurityManager(b"\x01" * (MIN_KEY_BYTES - 1))


def test_rechaza_clave_que_no_es_bytes():
    with pytest.raises(ValueError):
        SecurityManager("a" * 64)


def test_acepta_clave_de_256_bits(key):
    assert SecurityManager(key).secret_key == key


def test_from_env_sin_variable(monkeypatch):
    monkeypatch.delenv("SECBANK_HMAC_KEY", raising=False)
    with pytest.raises(RuntimeError):
        SecurityManager.from_env()


def test_from_env_ok(monkeypatch):
    monkeypatch.setenv("SECBANK_HMAC_KEY", "ab" * 32)
    assert SecurityManager.from_env().secret_key == bytes.fromhex("ab" * 32)


def test_from_env_clave_corta(monkeypatch):
    monkeypatch.setenv("SECBANK_HMAC_KEY", "ab" * 8)
    with pytest.raises(ValueError):
        SecurityManager.from_env()


# ---------- Nonce y timestamp (RS3) ----------
def test_nonce_es_uuid4_en_minusculas():
    n = SecurityManager.generate_nonce()
    assert UUID4_RE.match(n)
    assert uuid.UUID(n).version == 4


def test_nonces_no_se_repiten():
    assert len({SecurityManager.generate_nonce() for _ in range(1000)}) == 1000


def test_timestamp_es_entero_en_segundos():
    import time
    ts = SecurityManager.get_timestamp()
    assert isinstance(ts, int)
    assert abs(ts - time.time()) < 2


# ---------- Cuerpo canónico ----------
def test_canonical_body_ordena_claves_y_es_compacto():
    assert SecurityManager.canonical_body({"b": 1, "a": 2}) == b'{"a":2,"b":1}'


def test_canonical_body_es_determinista():
    a = SecurityManager.canonical_body({"x": 1, "y": [1, 2], "z": "ñ"})
    b = SecurityManager.canonical_body({"z": "ñ", "y": [1, 2], "x": 1})
    assert a == b


def test_canonical_body_utf8_sin_escapar():
    assert "ñ".encode("utf-8") in SecurityManager.canonical_body({"n": "ñ"})


def test_canonical_body_rechaza_nan():
    with pytest.raises(ValueError):
        SecurityManager.canonical_body({"amount": float("nan")})


# ---------- Firma HMAC-SHA256 (RS2a) ----------
def test_firma_coincide_con_formato_acordado(manager, key):
    """Mensaje = f"{timestamp}\\n{nonce}\\n" + body; es el formato que verifica el servidor."""
    body = b'{"a":1}'
    nonce = "d9b2a7e4-3c11-4b8a-8e22-1a4f5e6d7c8b"
    ts = 1741690000
    esperado = hmac.new(key, f"{ts}\n{nonce}\n".encode() + body, hashlib.sha256).hexdigest()
    assert manager.generate_signature(body, nonce, ts) == esperado


def test_firma_es_hex_de_64_caracteres(manager):
    sig = manager.generate_signature(b"{}", "n", 1)
    assert re.fullmatch(r"[0-9a-f]{64}", sig)


@pytest.mark.parametrize("cambio", ["body", "nonce", "timestamp", "clave"])
def test_cualquier_cambio_altera_la_firma(manager, cambio):
    base = dict(body=b'{"amount":200}', nonce="n1", ts=100)
    sig = manager.generate_signature(base["body"], base["nonce"], base["ts"])
    if cambio == "body":
        otra = manager.generate_signature(b'{"amount":2000}', base["nonce"], base["ts"])
    elif cambio == "nonce":
        otra = manager.generate_signature(base["body"], "n2", base["ts"])
    elif cambio == "timestamp":
        otra = manager.generate_signature(base["body"], base["nonce"], 101)
    else:
        otra = SecurityManager(b"\x22" * 32).generate_signature(base["body"], base["nonce"], base["ts"])
    assert otra != sig


def test_firma_estable_para_mismos_datos(manager):
    assert manager.generate_signature(b"x", "n", 5) == manager.generate_signature(b"x", "n", 5)
