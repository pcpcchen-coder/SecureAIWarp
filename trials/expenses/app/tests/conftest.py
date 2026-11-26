import socket
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))


@pytest.fixture(autouse=True)
def no_network(monkeypatch):
    """測試期間禁止任何真實網路連線。"""
    def guard(*a, **k):
        raise RuntimeError("tests must not use the network")
    monkeypatch.setattr(socket, "create_connection", guard)
    monkeypatch.setattr(socket.socket, "connect", guard)
