import logging
import re
import time

from fastapi import Depends, Header, HTTPException, Request
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from database.database import get_db
from database.models import Nonce
from .crypto import verify_hmac

logger = logging.getLogger("secbank.security")

# Ventana de validez del timestamp: +-30 segundos respecto a la hora del servidor.
TIMESTAMP_WINDOW = 30
# Tiempo que se conserva un nonce. Un mensaje con timestamp t solo es aceptable hasta t + 30 s, así que 60 s da margen de sobra.
NONCE_TTL = 60

# UUIDv4 estricto en minúsculas. Importante: solo minúsculas, porque en la BD "ABC..." y "abc..." serían nonces distintos y permitirían burlar el anti-replay.
UUID4_RE = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
)


def _reject(status_code: int, message: str, reason: str, nonce: str = None):
    """Registra el rechazo en el log y lanza la excepción HTTP."""
    # repr() + recorte: evita que un atacante inyecte saltos de línea en el log.
    logger.warning(
        "RECHAZADO [%s] nonce=%r", reason, (nonce or "")[:64]
    )
    raise HTTPException(status_code=status_code, detail={"error": message})


async def security_validation(
    request: Request,
    timestamp: int = Header(None, alias="X-Timestamp"),
    nonce: str = Header(None, alias="X-Nonce"),
    signature: str = Header(None, alias="X-Signature"),
    db: Session = Depends(get_db),
):
    """
    Valida la seguridad de cada petición entrante, de la comprobación más
    barata a la más cara:
      1. Cabeceras presentes
      2. Timestamp dentro de la ventana
      3. Formato del nonce (UUIDv4)
      4. Firma HMAC (tiempo constante)
      5. Nonce no reutilizado (inserción atómica) + purga de nonces caducados
    """

    # 1. Cabeceras presentes
    if timestamp is None or nonce is None or signature is None:
        _reject(400, "Faltan cabeceras de seguridad.", "cabeceras_ausentes", nonce)

    # 2. Ventana temporal
    current_time = int(time.time())
    if abs(current_time - timestamp) > TIMESTAMP_WINDOW:
        _reject(401, "La solicitud ha expirado.", "timestamp_fuera_de_ventana", nonce)

    # 3. Formato del nonce
    if not UUID4_RE.match(nonce):
        _reject(400, "Formato de nonce inválido.", "nonce_formato_invalido", nonce)

    # 4. Firma HMAC
    body = await request.body()
    if not verify_hmac(str(timestamp), nonce, body, signature):
        _reject(401, "Firma inválida.", "firma_invalida", nonce)

    # 5. Nonce: purga de caducados + inserción atómica. La restricción UNIQUE/PRIMARY KEY de la columna 'nonce' es la que garantiza que, ante dos peticiones simultáneas idénticas, solo una se inserta; la otra provoca IntegrityError.
    try:
        db.query(Nonce).filter(Nonce.timestamp < current_time - NONCE_TTL).delete()
        db.add(Nonce(nonce=nonce, timestamp=timestamp))
        db.commit()
    except IntegrityError:
        db.rollback()
        _reject(401, "Nonce ya utilizado.", "replay_nonce_repetido", nonce)

    logger.info("ACEPTADO nonce=%r", nonce)
    return Tru