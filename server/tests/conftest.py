"""
Fixtures compartidas por todos los tests.

Los tests NO necesitan el servidor arrancado ni la variable de entorno real:
usan una clave de prueba propia y una base de datos SQLite en memoria.
"""
import hashlib
import hmac
import os
import time
import uuid

# IMPORTANTE: la clave debe existir ANTES de importar security.crypto,
# porque crypto.py la lee (y valida) al importarse.
TEST_KEY = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"
os.environ["SECBANK_HMAC_KEY"] = TEST_KEY

import pytest  # noqa: E402
from fastapi import Depends, FastAPI, Request  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402
from sqlalchemy import create_engine  # noqa: E402
from sqlalchemy.orm import sessionmaker  # noqa: E402
from sqlalchemy.pool import StaticPool  # noqa: E402

from database.database import Base, get_db  # noqa: E402
import database.models  # noqa: E402,F401  (registra las tablas en Base)
from security.middleware import security_validation  # noqa: E402

BODY = b'{"tx_id": "f47ac10b-58cc-4372-a567-0e02b2c3d479", "amount": 1250.75}'


@pytest.fixture()
def body():
    """Cuerpo de ejemplo de una petición."""
    return BODY


@pytest.fixture()
def session_factory():
    """BD SQLite en memoria, nueva en cada test (no toca secbank.db)."""
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(bind=engine)
    yield sessionmaker(bind=engine, autoflush=False)
    engine.dispose()


@pytest.fixture()
def client(session_factory):
    """Mini-app con UNA ruta falsa protegida por tu middleware."""
    app = FastAPI(dependencies=[Depends(security_validation)])

    @app.post("/echo")
    async def echo(request: Request):
        return {"ok": True}

    def override_get_db():
        db = session_factory()
        try:
            yield db
        finally:
            db.close()

    app.dependency_overrides[get_db] = override_get_db
    return TestClient(app)


@pytest.fixture()
def sign():
    """
    Devuelve una función que construye las cabeceras de seguridad de un
    cliente legítimo. El HMAC se calcula AQUÍ con hmac/hashlib directamente
    (no con crypto.generate_hmac) para validar de forma independiente el
    formato:  timestamp \\n nonce \\n body
    """

    def _sign(body=BODY, timestamp=None, nonce=None):
        ts = int(time.time()) if timestamp is None else timestamp
        n = str(uuid.uuid4()) if nonce is None else nonce
        msg = f"{ts}\n{n}\n".encode("utf-8") + body
        signature = hmac.new(bytes.fromhex(TEST_KEY), msg, hashlib.sha256).hexdigest()
        return {
            "X-Timestamp": str(ts),
            "X-Nonce": n,
            "X-Signature": signature,
            "Content-Type": "application/json",
        }

    return _sign
