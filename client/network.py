import json
import os
import urllib.error
import urllib.request

from security import SecurityManager

# Restriction: no TLS/HTTPS allowed, only HTTP.
DEFAULT_BASE_URL = os.environ.get("SECBANK_URL", "http://127.0.0.1:8000") # Defines the client connection URL, which can be set through an environment variable or be a default value
TIMEOUT = 5 # Limit the request time to 5 seconds to avoid blocking the main thread


class SecBankClient: # Manages the client-server REST API communication
    # Class Constructor 
    def __init__(self, security: SecurityManager, base_url: str = DEFAULT_BASE_URL):
        """Initializes the SecBankClient with a SecurityManager and a base URL for the server."""
        if not base_url.startswith("http://"):
            raise ValueError("Prohibido TLS/HTTPS: usa http://") # Restriction: no TLS/HTTPS allowed, only HTTP.
        self.security = security
        self.base_url = base_url
        self.session_token = None
        self.last_error = None # Last error message from the server (shown by the UI)
        self.last_request = None  # Includes (url, headers, body) -> Only for testing purposes

    # Method to send POST requests to the server
    def _post(self, path: str, payload: dict, auth: bool = False, timestamp: int = None) -> dict:
        """Sends a POST request to the server, using the security manager to sign the request"""
        if auth and not self.session_token: # Check if the user is authenticated before sending a request that requires authentication
            return {"success": False, "error": "Usuario no autenticado. Inicia sesión primero."}
        body = self.security.canonical_body(payload) # Changes dictionary to a JSON string
        ts = timestamp if timestamp is not None else self.security.get_timestamp() # Uses the provided ts or generates a new one
        nonce = self.security.generate_nonce() # Assigns a random nonce to the request
        headers = { # Creates the headers for the request
            "Content-Type": "application/json",
            "X-Signature": self.security.generate_signature(body, nonce, ts), # Assigns a signature generated with HMAC-SHA256
            "X-Nonce": nonce, # Assigns the nonce, so the server can check for replay attacks before verifying the signature
            "X-Timestamp": str(ts), # Assigns the timestamp, so the server knows when the request was made before verifying the signature
        }
        if auth:
            headers["Authorization"] = f"Bearer {self.session_token}" # Adds the session token to the headers if the request requires authentication
        url = f"{self.base_url}{path}"
        self.last_request = (url, headers, body) # Saves the last request for testing purposes

        req = urllib.request.Request(url, data=body, headers=headers, method="POST") # Creates the POST request
        try: # Sends the request, waits for the response a timeout of 5 seconds and reads the response
            with urllib.request.urlopen(req, timeout=TIMEOUT) as r: 
                raw = r.read().decode("utf-8") 
        except urllib.error.HTTPError as e:  # If there is an HTTP error, it shows the code (4xx / 5xx) and extracts the human readable message
            return {"success": False, "error":self._error_message(e.read().decode("utf-8", "replace")), "status": e.code}
        except (urllib.error.URLError, TimeoutError, OSError) as e: # If there is a network error, it shows the error message
            return {"success": False, "error": str(e)}
        try: # Tries to parse the response as JSON, if it fails, it returns the raw response
            return {"success": True, "data": json.loads(raw)}
        except ValueError:
            return {"success": True, "data": raw}

    # Function to extract the human readable message from FastAPI error bodies
    @staticmethod
    def _error_message(raw: str) -> str:
        """Extracts the human readable message from FastAPI error bodies, which are usually JSON with a 'detail' field."""
        try: # Tries to parse the response as JSON and extract the 'detail' field, if it fails, it returns the raw response
            detail = json.loads(raw).get("detail", raw)
        except (ValueError, AttributeError):
            return raw
        if isinstance(detail, list): # If detail is a list, it concatenates the messages into a single string
            return "; ".join(str(d.get("msg", d)) if isinstance(d, dict) else str(d) for d in detail)
        return str(detail) # If detail is a string, it returns it as is

    # Function to register a new user
    def register(self, username: str, password: str) -> bool:
        """Sends the registration request. Returns True if the server created the user."""
        res = self._post("/auth/register", {"username": username, "password": password}) # Sends the username and password to the server for registration
        self.last_error = None if res["success"] else res.get("error") # If the registration was successful, it clears the last error message, otherwise it saves the error message from the server
        return res["success"]
    
    # Function to log in the user and store the session token
    def login(self, username: str, password: str) -> bool: 
        """Sends the login request to the server and stores the session token"""
        res = self._post("/auth/login", {"username": username, "password": password}) # Sends the username and password to the server
        self.last_error = None if res["success"] else res.get("error") # If the login was successful, it clears the last error message, otherwise it saves the error message from the server
        if res["success"] and isinstance(res["data"], dict): # If the response is successful and the data is a dictionary
            self.session_token = res["data"].get("access_token") # Stores the session token in the client
        return bool(self.session_token) # Returns True if the session token is not None, False otherwise

    # Function to log out the user and invalidate the session token
    def logout(self): 
        """Warns the server (to invalidate the session) and deletes the local token."""
        if self.session_token:
            self._post("/auth/logout", {}, auth=True)
        self.session_token = None

    # Function to send a transfer request to the server
    def send_transfer(self, payload: dict) -> dict:
        """Sends a transfer request to the server, it requires authentication and a timestamp"""
        return self._post("/transfer", payload, auth=True, timestamp=payload["timestamp"]) # Sends the transfer request to the server