import json
import urllib.error
import io

import pytest

from network import SecBankClient


def headers_of(req):
    # urllib normaliza los nombres de cabecera (X-signature, X-nonce...)
    return {k.lower(): v for k, v in req.header_items()}


@pytest.fixture
def client(manager):
    return SecBankClient(manager)


# ---------- Restricción: sin TLS ----------
@pytest.mark.parametrize("url", ["https://127.0.0.1:8000", "ftp://x", "127.0.0.1:8000"])
def test_rechaza_urls_que_no_son_http(manager, url):
    with pytest.raises(ValueError):
        SecBankClient(manager, base_url=url)


def test_acepta_http(manager):
    assert SecBankClient(manager, base_url="http://127.0.0.1:9").base_url == "http://127.0.0.1:9"


# ---------- Cabeceras de seguridad ----------
def test_post_incluye_cabeceras_y_firma_valida(client, manager, capture):
    client._post("/auth/login", {"username": "u", "password": "p"})
    req = capture["req"]
    h = headers_of(req)
    assert req.get_method() == "POST"
    assert req.full_url == "http://127.0.0.1:8000/auth/login"
    for nombre in ("x-signature", "x-nonce", "x-timestamp"):
        assert nombre in h
    esperado = manager.generate_signature(req.data, h["x-nonce"], int(h["x-timestamp"]))
    assert h["x-signature"] == esperado


def test_cada_peticion_usa_un_nonce_distinto(client, capture):
    nonces = []
    for _ in range(5):
        client._post("/auth/login", {"a": 1})
        nonces.append(headers_of(capture["req"])["x-nonce"])
    assert len(set(nonces)) == 5


def test_cuerpo_enviado_es_el_canonico(client, manager, capture):
    payload = {"b": 2, "a": 1}
    client._post("/x", payload)
    assert capture["req"].data == manager.canonical_body(payload)


def test_timeout_configurado(client, capture):
    client._post("/x", {})
    assert capture["timeout"] == 5


# ---------- Sesión ----------
def test_post_autenticado_sin_token_no_envia_nada(client, capture):
    res = client._post("/transfer", {}, auth=True)
    assert res["success"] is False
    assert capture["req"] is None


def test_login_guarda_token_y_lo_manda_en_authorization(client, capture):
    capture["body"] = json.dumps({"access_token": "tok123", "token_type": "bearer"}).encode()
    assert client.login("u", "p") is True
    assert client.session_token == "tok123"
    client.send_transfer({"tx_id": "t", "origin_account": "a", "destination_account": "b",
                          "amount": 1.0, "currency": "EUR"})
    assert headers_of(capture["req"])["authorization"] == "Bearer tok123"


def test_login_fallido_limpia_token(client, capture):
    client.session_token = "viejo"
    capture["error"] = urllib.error.HTTPError(
        "u", 401, "x", {}, io.BytesIO(b'{"detail": "Credenciales inv\\u00e1lidas"}'))
    assert client.login("u", "mala") is False
    assert client.session_token is None
    assert client.last_error == "Credenciales inválidas"


def test_logout_avisa_al_servidor_y_borra_token(client, capture):
    client.session_token = "tok"
    client.logout()
    assert capture["req"].full_url.endswith("/auth/logout")
    assert client.session_token is None


def test_logout_sin_sesion_no_hace_peticion(client, capture):
    client.logout()
    assert capture["req"] is None


def test_register_ok_y_error(client, capture):
    assert client.register("u", "password1") is True and client.last_error is None
    capture["error"] = urllib.error.HTTPError(
        "u", 409, "x", {}, io.BytesIO(b'{"detail": "El usuario ya existe."}'))
    assert client.register("u", "password1") is False
    assert client.last_error == "El usuario ya existe."


# ---------- Transferencias ----------
def test_timestamp_del_cuerpo_igual_al_de_la_cabecera(client, capture):
    """El timestamp se fija justo antes de enviar y debe coincidir en cuerpo y cabecera."""
    client.session_token = "tok"
    client.send_transfer({"tx_id": "t", "origin_account": "ES" + "1" * 22,
                          "destination_account": "ES" + "2" * 22, "amount": 5.0, "currency": "EUR",
                          "timestamp": 1})  # un timestamp viejo no debe sobrevivir
    req = capture["req"]
    body = json.loads(req.data)
    assert body["timestamp"] == int(headers_of(req)["x-timestamp"])
    assert body["timestamp"] != 1


def test_send_transfer_no_muta_el_payload(client, capture):
    client.session_token = "tok"
    payload = {"tx_id": "t", "amount": 1.0}
    client.send_transfer(payload)
    assert "timestamp" not in payload


# ---------- Errores de red y de formato ----------
def test_error_de_red_se_devuelve_sin_excepcion(client, capture):
    capture["error"] = urllib.error.URLError("conexión rehusada")
    res = client._post("/x", {})
    assert res["success"] is False and "conexión rehusada" in res["error"]


def test_respuesta_no_json_se_devuelve_en_crudo(client, capture):
    capture["body"] = b"texto plano"
    assert client._post("/x", {}) == {"success": True, "data": "texto plano"}


@pytest.mark.parametrize("raw, esperado", [
    ('{"detail": "msg"}', "msg"),
    ('{"detail": {"error": "firma mala"}}', "firma mala"),
    ('{"detail": [{"msg": "campo requerido"}, {"msg": "otro"}]}', "campo requerido; otro"),
    ("no es json", "no es json"),
])
def test_error_message(raw, esperado):
    assert SecBankClient._error_message(raw) == esperado
