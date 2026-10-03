import hashlib
import hmac
import json
import os
import time
import uuid
from dotenv import load_dotenv

load_dotenv() # Loads environment variables from a .env file, if it exists

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
            raise RuntimeError(f"Error: La variable {var} no está configurada en el archivo .env o en el sistema.Define {var} (genera una con: python -c \"import secrets;print(secrets.token_hex(32))\")")
        return cls(bytes.fromhex(value))

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