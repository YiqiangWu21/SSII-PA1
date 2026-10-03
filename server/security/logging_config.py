"""
Configuración del log de seguridad.

Guarda cada aceptación y cada rechazo del middleware en logs/security.log
(evidencia para la memoria) y los muestra también por consola.

Uso (una vez, al arrancar el servidor, en main.py):
    from security.logging_config import setup_security_logging
    setup_security_logging()
"""
import logging
from pathlib import Path

LOGGER_NAME = "secbank.security"
DEFAULT_LOG_DIR = Path(__file__).resolve().parents[1] / "logs"
LOG_FORMAT = "%(asctime)s | %(levelname)s | %(message)s"


def setup_security_logging(log_dir=None, level=logging.INFO) -> Path:
    """Configura el logger de seguridad y devuelve la ruta del fichero de log."""
    log_dir = Path(log_dir) if log_dir else DEFAULT_LOG_DIR
    log_dir.mkdir(parents=True, exist_ok=True)
    log_file = log_dir / "security.log"

    logger = logging.getLogger(LOGGER_NAME)
    logger.setLevel(level)
    logger.propagate = False  # evita líneas duplicadas por consola

    # Idempotente: si se llama dos veces no se duplican los manejadores.
    for handler in list(logger.handlers):
        logger.removeHandler(handler)
        handler.close()

    formatter = logging.Formatter(LOG_FORMAT)

    file_handler = logging.FileHandler(log_file, encoding="utf-8")
    file_handler.setFormatter(formatter)
    logger.addHandler(file_handler)

    console_handler = logging.StreamHandler()
    console_handler.setFormatter(formatter)
    logger.addHandler(console_handler)

    return log_file
