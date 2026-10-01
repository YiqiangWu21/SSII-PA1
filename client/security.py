import hashlib
import hmac
import json
import os
import secrets
import time
import uuid

MIN_KEY_BYTES = 32  # Defines the minimum key length in bytes (>= 256 bits)


class SecurityManager:
    # Class constructor
    def __init__(self, secret_key: bytes):
        """Initializes the SecurityManager with a secret key for HMAC operations."""
        if not isinstance(secret_key, (bytes, bytearray)) or len(secret_key) < MIN_KEY_BYTES: # Checks if the secret key has a minimum length of 32 bytes (256 bits)
            raise ValueError("La clave HMAC debe ser bytes y tener al menos 256 bits (32 bytes)")
        self.secret_key = bytes(secret_key) # Stores the secret key as bytes for HMAC operations

    # Function to create a SecurityManager instance from an environment variable
    @classmethod
    def from_env(cls, var: str = "SECBANK_HMAC_KEY") -> "SecurityManager":
        """Reads the key (hex, 64 characters) from an environment variable; never in the code."""
        value = os.environ.get(var) # Reads the value of the environment variable
        if not value: # If the environment variable is not set, it raises a RuntimeError with instructions to generate a new key
            raise RuntimeError(f"Define {var} (genera una con: python -c \"import secrets;print(secrets.token_hex(32))\")")
        return cls(bytes.fromhex(value))

    # Function to generate a new random key for HMAC operations
    @staticmethod
    def generate_key() -> str:
        """Generates a new random key for HMAC operations."""
        return secrets.token_hex(32)  # Generates a random 256-bit key and returns it as a hexadecimal string

    # Function to generate a random nonce for request signing
    @staticmethod
    def generate_nonce() -> str:
        """Generates a random nonce for request signing."""
        return str(uuid.uuid4()) # Generates a random UUID4 string to be used as a nonce for request signing

    # Function to get the current timestamp in seconds
    @staticmethod
    def get_timestamp() -> int:
        """Returns the current timestamp in seconds."""
        return int(time.time())

    # Function to create a canonical JSON representation of a payload for signing
    @staticmethod
    def canonical_body(payload: dict) -> bytes:
        """Creates a canonical JSON representation of a payload that is consistent between systems."""
        return json.dumps(payload, separators=(",", ":"), sort_keys=True,
                          ensure_ascii=False, allow_nan=False).encode("utf-8")

    # Function to generate an HMAC-SHA256 signature for a request
    def generate_signature(self, body: bytes, nonce: str, timestamp: int) -> str:
        """Generates an HMAC-SHA256 signature for a request, using the nonce and the timestamp."""
        msg = f"{timestamp}\n{nonce}\n".encode("utf-8") + body # Creates the message, by concatenating the timestamp, nonce, and body
        return hmac.new(self.secret_key, msg, hashlib.sha256).hexdigest()

    # Function to verify an HMAC-SHA256 signature for a request
    def verify_signature(self, body: bytes, nonce: str, timestamp: int, signature: str) -> bool:
        """Verifies an HMAC-SHA256 signature for a request, using the nonce and the timestamp."""
        expected = self.generate_signature(body, nonce, timestamp) # Generates a new signature using the same parameters
        return hmac.compare_digest(expected.encode("utf-8"), signature.encode("utf-8", "replace")) # Constant-time comparison over bytes