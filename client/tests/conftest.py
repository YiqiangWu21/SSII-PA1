import pytest

TEST_KEY_HEX = "11" * 32  # 256 bits, solo para tests


@pytest.fixture
def key():
    return bytes.fromhex(TEST_KEY_HEX)


@pytest.fixture
def manager(key):
    from security import SecurityManager
    return SecurityManager(key)


class FakeResponse:
    """Respuesta mínima compatible con urllib.request.urlopen (context manager)."""

    def __init__(self, body: bytes = b"{}"):
        self._body = body

    def read(self):
        return self._body

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


@pytest.fixture
def capture(monkeypatch):
    """Sustituye urlopen y guarda la última petición enviada."""
    import network

    state = {"req": None, "body": b'{"ok": true}', "error": None}

    def fake_urlopen(req, timeout=None):
        state["req"] = req
        state["timeout"] = timeout
        if state["error"] is not None:
            raise state["error"]
        return FakeResponse(state["body"])

    monkeypatch.setattr(network.urllib.request, "urlopen", fake_urlopen)
    return state
