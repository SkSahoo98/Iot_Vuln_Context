"""Assistant explanation tests: no database, no Ollama, no network."""

from __future__ import annotations

import socket
import sys
from pathlib import Path

import pytest

BACKEND_ROOT = Path(__file__).resolve().parents[1]
PROJECT_ROOT = BACKEND_ROOT.parent
for path in (BACKEND_ROOT, PROJECT_ROOT):
    if str(path) not in sys.path:
        sys.path.insert(0, str(path))


@pytest.fixture(autouse=True)
def no_network(monkeypatch):
    """Any outbound connection during these tests is a failure."""

    real_connect = socket.socket.connect

    def refuse(*args, **kwargs):
        raise AssertionError(f"network access attempted: {args!r}")

    def loopback_pair_only(sock, address):
        # On Windows the asyncio event loop builds its self-pipe from a
        # loopback socketpair; every other raw connect is refused.
        if sock.family == socket.AF_INET and address[0] == "127.0.0.1":
            return real_connect(sock, address)
        refuse(sock, address)

    monkeypatch.setattr(socket.socket, "connect", loopback_pair_only)
    monkeypatch.setattr(socket.socket, "connect_ex", refuse)
    monkeypatch.setattr(socket, "create_connection", refuse)


@pytest.fixture(autouse=True)
def fresh_cache():
    from app.services import assistant_service

    assistant_service.clear_cache()
    yield
    assistant_service.clear_cache()
