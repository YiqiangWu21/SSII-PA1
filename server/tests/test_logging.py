"""Test de security/logging_config.py: el log de seguridad se escribe en fichero."""
import logging

from security.logging_config import LOGGER_NAME, setup_security_logging


def _limpiar(logger):
    for handler in list(logger.handlers):
        logger.removeHandler(handler)
        handler.close()
    logger.propagate = True
    logger.setLevel(logging.NOTSET)


def test_el_log_se_escribe_en_fichero(tmp_path):
    logger = logging.getLogger(LOGGER_NAME)
    try:
        log_file = setup_security_logging(tmp_path)
        logger.info("ACEPTADO nonce=%r", "n-1")
        logger.warning("RECHAZADO [replay_nonce_repetido] nonce=%r", "n-1")
        for handler in logger.handlers:
            handler.flush()

        contenido = log_file.read_text(encoding="utf-8")
        assert "ACEPTADO" in contenido
        assert "RECHAZADO [replay_nonce_repetido]" in contenido
    finally:
        _limpiar(logger)


def test_llamarlo_dos_veces_no_duplica_manejadores(tmp_path):
    logger = logging.getLogger(LOGGER_NAME)
    try:
        setup_security_logging(tmp_path)
        setup_security_logging(tmp_path)
        assert len(logger.handlers) == 2  # un fichero + una consola
    finally:
        _limpiar(logger)
