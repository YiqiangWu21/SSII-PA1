import json
import urllib.error
import urllib.request

from security import SecurityManager

# Restricción del enunciado: HTTP en texto plano, SIN TLS/HTTPS.
DEFAULT_BASE_URL = "http://127.0.0.1:8000"
TIMEOUT = 5


class SecBankClient:
    def __init__(self, security: SecurityManager, base_url: str = DEFAULT_BASE_URL):
        if not base_url.startswith("http://"):
            raise ValueError("Prohibido TLS/HTTPS: usa http://")
        self.security = security
        self.base_url = base_url
        self.session_token = None
        self.last_request = None  # (url, headers, body) -> útil para tests y evidencias

    def _post(self, path: str, payload: dict, auth: bool = False, timestamp: int = None) -> dict:
        if auth and not self.session_token:
            return {"success": False, "error": "Usuario no autenticado. Inicia sesión primero."}
        body = self.security.canonical_body(payload)
        ts = timestamp if timestamp is not None else self.security.get_timestamp()
        nonce = self.security.generate_nonce()
        headers = {
            "Content-Type": "application/json",
            "X-Signature": self.security.generate_signature(body, nonce, ts),
            "X-Nonce": nonce,
            "X-Timestamp": str(ts),
        }
        if auth:
            headers["Authorization"] = f"Bearer {self.session_token}"
        url = f"{self.base_url}{path}"
        self.last_request = (url, headers, body)

        req = urllib.request.Request(url, data=body, headers=headers, method="POST")
        try:
            with urllib.request.urlopen(req, timeout=TIMEOUT) as r:
                raw = r.read().decode("utf-8")
        except urllib.error.HTTPError as e:  # 4xx / 5xx
            return {"success": False, "error": e.read().decode("utf-8", "replace"), "status": e.code}
        except (urllib.error.URLError, TimeoutError, OSError) as e:
            return {"success": False, "error": str(e)}
        try:
            return {"success": True, "data": json.loads(raw)}
        except ValueError:
            return {"success": True, "data": raw}

    def login(self, username: str, password: str) -> bool:
        res = self._post("/auth/login", {"username": username, "password": password})
        if res["success"] and isinstance(res["data"], dict):
            self.session_token = res["data"].get("access_token")
        return bool(self.session_token)

    def logout(self):
        """Avisa al servidor (para invalidar la sesión) y borra el token local."""
        if self.session_token:
            self._post("/auth/logout", {}, auth=True)
        self.session_token = None

    def send_transfer(self, payload: dict) -> dict:
        # El timestamp de la cabecera es el mismo que va en el JSON.
        return self._post("/transfer", payload, auth=True, timestamp=payload["timestamp"])