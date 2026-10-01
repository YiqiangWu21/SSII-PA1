"""
Tests del middleware de seguridad (security/middleware.py).
Cada test corresponde a un control del enunciado (RS2, RS3, RS4).
"""
import logging
import time
import uuid

import pytest

from database.models import Nonce


def count_nonces(session_factory) -> int:
    db = session_factory()
    try:
        return db.query(Nonce).count()
    finally:
        db.close()


def error_msg(response) -> str:
    return response.json()["detail"]["error"]


# ---------------------------------------------------------------- caso legítimo

def test_peticion_legitima_es_aceptada(client, sign, body):
    r = client.post("/echo", content=body, headers=sign(body))
    assert r.status_code == 200


# ------------------------------------------------------------ cabeceras ausentes

def test_sin_cabeceras_de_seguridad_400(client, body):
    r = client.post("/echo", content=body)
    assert r.status_code == 400
    assert error_msg(r) == "Faltan cabeceras de seguridad."


@pytest.mark.parametrize("faltante", ["X-Timestamp", "X-Nonce", "X-Signature"])
def test_falta_una_cabecera_400(client, sign, body, faltante):
    headers = sign(body)
    del headers[faltante]
    r = client.post("/echo", content=body, headers=headers)
    assert r.status_code == 400


# ------------------------------------------------- MitM: integridad (RS2)

def test_mitm_cuerpo_alterado_es_rechazado(client, sign, body):
    """El atacante cambia el importe en tránsito; la firma ya no cuadra."""
    headers = sign(body)  # firma del cuerpo original
    cuerpo_alterado = body.replace(b"1250.75", b"9999.99")
    r = client.post("/echo", content=cuerpo_alterado, headers=headers)
    assert r.status_code == 401
    assert error_msg(r) == "Firma inválida."


def test_mitm_firma_alterada_es_rechazada(client, sign, body):
    headers = sign(body)
    firma = headers["X-Signature"]
    # Cambiamos solo el último carácter de la firma
    headers["X-Signature"] = firma[:-1] + ("0" if firma[-1] != "0" else "1")
    r = client.post("/echo", content=body, headers=headers)
    assert r.status_code == 401
    assert error_msg(r) == "Firma inválida."


def test_firma_con_clave_incorrecta_es_rechazada(client, sign, body):
    headers = sign(body)
    headers["X-Signature"] = "0" * 64
    r = client.post("/echo", content=body, headers=headers)
    assert r.status_code == 401


def test_timestamp_alterado_invalida_la_firma(client, sign, body):
    """El timestamp también va firmado: no se puede 'refrescar' un paquete."""
    headers = sign(body)
    headers["X-Timestamp"] = str(int(headers["X-Timestamp"]) + 1)
    r = client.post("/echo", content=body, headers=headers)
    assert r.status_code == 401
    assert error_msg(r) == "Firma inválida."


# --------------------------------------------------------- Replay (RS3)

def test_replay_mismo_paquete_es_rechazado(client, sign, body, session_factory):
    """Se reenvía EXACTAMENTE el mismo paquete capturado."""
    headers = sign(body)
    primero = client.post("/echo", content=body, headers=headers)
    segundo = client.post("/echo", content=body, headers=headers)

    assert primero.status_code == 200
    assert segundo.status_code == 401
    assert error_msg(segundo) == "Nonce ya utilizado."
    assert count_nonces(session_factory) == 1


@pytest.mark.parametrize("delta", [-60, 60])
def test_timestamp_fuera_de_ventana_es_rechazado(client, sign, body, delta):
    """Paquete antiguo (-60 s) o del futuro (+60 s), con firma correcta."""
    headers = sign(body, timestamp=int(time.time()) + delta)
    r = client.post("/echo", content=body, headers=headers)
    assert r.status_code == 401
    assert error_msg(r) == "La solicitud ha expirado."


def test_timestamp_dentro_de_ventana_es_aceptado(client, sign, body):
    headers = sign(body, timestamp=int(time.time()) - 10)
    r = client.post("/echo", content=body, headers=headers)
    assert r.status_code == 200


# ---------------------------------------------------- Formato del nonce

@pytest.mark.parametrize(
    "nonce",
    [
        "abc",                                       # no es UUID
        str(uuid.uuid4()).upper(),                   # mayúsculas: bypass del replay
        uuid.uuid4().hex,                            # sin guiones
        "123e4567-e89b-12d3-a456-426614174000",      # UUID versión 1, no v4
    ],
)
def test_nonce_con_formato_invalido_es_rechazado(client, sign, body, nonce):
    # La firma es VÁLIDA: lo que falla es solo el formato del nonce.
    headers = sign(body, nonce=nonce)
    r = client.post("/echo", content=body, headers=headers)
    assert r.status_code == 400
    assert error_msg(r) == "Formato de nonce inválido."


def test_nonce_en_mayusculas_no_permite_burlar_el_replay(client, sign, body):
    """El mismo UUID en mayúsculas no debe colarse como nonce 'nuevo'."""
    nonce = str(uuid.uuid4())
    assert client.post("/echo", content=body, headers=sign(body, nonce=nonce)).status_code == 200
    r = client.post("/echo", content=body, headers=sign(body, nonce=nonce.upper()))
    assert r.status_code == 400


# ------------------------------------------- Orden de comprobaciones y purga

def test_firma_invalida_no_guarda_el_nonce(client, sign, body, session_factory):
    """Un atacante sin la clave no puede llenar la tabla de nonces."""
    headers = sign(body)
    headers["X-Signature"] = "f" * 64
    client.post("/echo", content=body, headers=headers)
    assert count_nonces(session_factory) == 0


def test_se_purgan_los_nonces_caducados(client, sign, body, session_factory):
    viejo = str(uuid.uuid4())
    db = session_factory()
    db.add(Nonce(nonce=viejo, timestamp=int(time.time()) - 1000))
    db.commit()
    db.close()
    assert count_nonces(session_factory) == 1

    r = client.post("/echo", content=body, headers=sign(body))
    assert r.status_code == 200

    db = session_factory()
    try:
        assert db.query(Nonce).filter_by(nonce=viejo).first() is None  # purgado
        assert db.query(Nonce).count() == 1                             # solo el nuevo
    finally:
        db.close()


# ------------------------------------------------------------------ Logging

def test_los_rechazos_quedan_registrados_en_el_log(client, sign, body, caplog):
    headers = sign(body)
    with caplog.at_level(logging.WARNING, logger="secbank.security"):
        client.post("/echo", content=body, headers=headers)  # aceptado
        client.post("/echo", content=body, headers=headers)  # replay
    assert "RECHAZADO [replay_nonce_repetido]" in caplog.text
