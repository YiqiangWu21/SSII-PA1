import hashlib
import hmac
import json
import os
import secrets
import time
import uuid

MIN_KEY_BYTES = 32  # RS2.b: >= 256 bits


class SecurityManager:
    def __init__(self, secret_key: bytes):
        if not isinstance(secret_key, (bytes, bytearray)) or len(secret_key) < MIN_KEY_BYTES:
            raise ValueError("La clave HMAC debe ser bytes y tener al menos 256 bits (32 bytes)")
        self.secret_key = bytes(secret_key)

    @classmethod
    def from_env(cls, var: str = "SECBANK_HMAC_KEY") -> "SecurityManager":
        """Lee la clave (hex, 64 caracteres) de una variable de entorno; nunca en el código."""
        value = os.environ.get(var)
        if not value:
            raise RuntimeError(f"Define {var} (genera una con: python -c \"import secrets;print(secrets.token_hex(32))\")")
        return cls(bytes.fromhex(value))

    @staticmethod
    def generate_key() -> str:
        return secrets.token_hex(32)  # CSPRNG, 256 bits

    @staticmethod
    def generate_nonce() -> str:
        return str(uuid.uuid4())

    @staticmethod
    def get_timestamp() -> int:
        return int(time.time())

    @staticmethod
    def canonical_body(payload: dict) -> bytes:
        """Serialización determinista. Estos MISMOS bytes son los que se firman y se envían."""
        return json.dumps(payload, separators=(",", ":"), sort_keys=True,
                          ensure_ascii=False, allow_nan=False).encode("utf-8")

    def generate_signature(self, body: bytes, nonce: str, timestamp: int) -> str:
        """HMAC-SHA256( timestamp \\n nonce \\n body ): nonce y timestamp quedan protegidos."""
        msg = f"{timestamp}\n{nonce}\n".encode("utf-8") + body
        return hmac.new(self.secret_key, msg, hashlib.sha256).hexdigest()

    def verify_signature(self, body: bytes, nonce: str, timestamp: int, signature: str) -> bool:
        expected = self.generate_signature(body, nonce, timestamp)
        return hmac.compare_digest(expected, signature)