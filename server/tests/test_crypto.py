"""
Tests de security/crypto.py: verificación HMAC (RS2/RS4) y carga de clave (RS2b).
"""
import importlib
import os

import pytest

import security.crypto as crypto
from conftest import TEST_KEY

KEY_ENV = "SECBANK_HMAC_KEY"


# ------------------------------------------------------------ verify_hmac

def test_firma_correcta_se_verifica():
    firma = crypto.generate_hmac("1741690000", "n-1", b"hola")
    assert crypto.verify_hmac("1741690000", "n-1", b"hola", firma) is True


def test_cuerpo_distinto_no_se_verifica():
    firma = crypto.generate_hmac("1741690000", "n-1", b"hola")
    assert crypto.verify_hmac("1741690000", "n-1", b"hola!", firma) is False


def test_firma_con_caracteres_no_ascii_devuelve_false_sin_lanzar_error():
    """Antes del arreglo esto lanzaba TypeError (-> error 500 en el servidor)."""
    assert crypto.verify_hmac("1", "n", b"x", "é" * 64) is False


def test_firma_vacia_devuelve_false():
    assert crypto.verify_hmac("1", "n", b"x", "") is False


def test_la_firma_es_hmac_sha256_hex_de_64_caracteres():
    firma = crypto.generate_hmac("1", "n", b"x")
    assert len(firma) == 64
    int(firma, 16)  # es hexadecimal válido


# ---------------------------------------------------- carga de la clave (RS2b)

@pytest.fixture(autouse=True)
def restaurar_crypto():
    """Tras cada test, deja el módulo crypto cargado con la clave de test."""
    yield
    os.environ[KEY_ENV] = TEST_KEY
    importlib.reload(crypto)


@pytest.mark.parametrize(
    "valor",
    [
        None,            # variable ausente
        "",              # vacía
        "zz" * 32,       # no es hexadecimal
        "ab" * 16,       # solo 128 bits (< 256)
        "00" * 32,       # 256 bits pero toda ceros (la clave por defecto antigua)
    ],
)
def test_clave_insegura_impide_arrancar(monkeypatch, valor):
    if valor is None:
        monkeypatch.delenv(KEY_ENV, raising=False)
    else:
        monkeypatch.setenv(KEY_ENV, valor)
    with pytest.raises(RuntimeError):
        importlib.reload(crypto)


def test_clave_valida_de_256_bits_se_acepta(monkeypatch):
    monkeypatch.setenv(KEY_ENV, "ab" * 32)
    modulo = importlib.reload(crypto)
    assert len(modulo.SECRET_KEY) == 32
