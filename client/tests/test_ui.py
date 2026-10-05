import re

import pytest

from ui import parse_amount, build_transfer

ORIGEN = "ES1234567890123456789012"
DESTINO = "ES9876543210987654321098"


# ---------- parse_amount ----------
@pytest.mark.parametrize("texto, esperado", [
    ("1500.50", 1500.50), ("1500,50", 1500.50), (" 20 ", 20.0), ("0.01", 0.01),
])
def test_parse_amount_validos(texto, esperado):
    assert parse_amount(texto) == esperado


@pytest.mark.parametrize("texto", ["abc", "", "0", "-5", "1.234", "nan", "inf", "-inf"])
def test_parse_amount_invalidos(texto):
    with pytest.raises(ValueError):
        parse_amount(texto)


# ---------- build_transfer ----------
def test_build_transfer_estructura_del_enunciado():
    tx = build_transfer(ORIGEN, DESTINO, 1500.50)
    assert set(tx) == {"tx_id", "origin_account", "destination_account", "amount", "currency", "timestamp"}
    assert tx["currency"] == "EUR"
    assert tx["amount"] == 1500.50
    assert isinstance(tx["timestamp"], int)
    assert re.fullmatch(r"[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}", tx["tx_id"])


def test_tx_id_unico():
    assert build_transfer(ORIGEN, DESTINO, 1)["tx_id"] != build_transfer(ORIGEN, DESTINO, 1)["tx_id"]


@pytest.mark.parametrize("origen, destino", [
    ("ES123", DESTINO), (ORIGEN, "XX9876543210987654321098"),
    ("es1234567890123456789012", DESTINO), (ORIGEN, ORIGEN),
])
def test_build_transfer_cuentas_invalidas(origen, destino):
    with pytest.raises(ValueError):
        build_transfer(origen, destino, 10)
