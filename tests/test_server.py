"""Security-relevant behaviour of the local server and the poller."""

import http.client
import json
import time
from pathlib import Path
from typing import Callable, List

import paramiko
import pytest

from cluster_monitor import server
from cluster_monitor.ssh_pool import UnknownHostKey, fingerprint

GOOD_OUTPUT = "@@nproc 4\n@@load 0 0 0\n@@mem 1 1 1\n@@gpu\n@@apps\n@@ps\n@@top\n"


class FakePool:
    """Stands in for SshPool; ``behaviour`` decides what each run() call does."""

    def __init__(self, behaviour: Callable[[int], str]) -> None:
        self.calls: List[str] = []
        self.trusted: List[str] = []
        self._behaviour = behaviour

    def run(self, node: str, script: str) -> str:
        self.calls.append(node)
        return self._behaviour(len(self.calls))

    def trust(self, hostname: str, key: paramiko.PKey) -> None:
        self.trusted.append(hostname)


def _wait_for(predicate: Callable[[], bool], timeout: float = 2.0) -> bool:
    end = time.time() + timeout
    while time.time() < end:
        if predicate():
            return True
        time.sleep(0.02)
    return predicate()


def test_auth_failure_is_not_retried() -> None:
    def refuse(_: int) -> str:
        raise paramiko.AuthenticationException("no")

    pool = FakePool(refuse)
    collector = server.Collector(pool, ("node5",), interval=0.01)  # type: ignore[arg-type]
    collector.start()
    assert _wait_for(lambda: collector.snapshot()[0].get("kind") == "auth")
    time.sleep(0.3)
    collector.stop()
    assert len(pool.calls) == 1


def test_unknown_host_key_waits_for_trust() -> None:
    key = paramiko.RSAKey.generate(1024)

    def first_unknown(call: int) -> str:
        if call == 1:
            raise UnknownHostKey("node19", key)
        return GOOD_OUTPUT

    pool = FakePool(first_unknown)
    collector = server.Collector(pool, ("node19",), interval=0.01)  # type: ignore[arg-type]
    collector.start()
    assert _wait_for(lambda: collector.snapshot()[0].get("kind") == "hostkey_unknown")
    time.sleep(0.2)
    assert len(pool.calls) == 1
    assert not collector.trust("node19", "SHA256:wrong")
    assert collector.trust("node19", fingerprint(key))
    assert _wait_for(lambda: collector.snapshot()[0].get("ok") is True)
    collector.stop()
    assert pool.trusted == ["node19"]


def test_unreachable_is_retried(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(server, "RETRY_INTERVAL", 0.01)

    def down(_: int) -> str:
        raise OSError("no route")

    pool = FakePool(down)
    collector = server.Collector(pool, ("node1",), interval=0.01)  # type: ignore[arg-type]
    collector.start()
    assert _wait_for(lambda: len(pool.calls) >= 3)
    collector.stop()


def test_http_requires_local_host_and_token(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(server, "data_dir", lambda: tmp_path)
    monkeypatch.setattr(server, "_bundled_defaults", lambda: {"jump_host": "login.example.edu"})
    app = server.App()
    httpd = server.start_server(app, 0)
    port = httpd.server_address[1]

    def request(method: str, path: str, host: str, token: str = "") -> http.client.HTTPResponse:
        conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
        headers = {"Host": host, "X-Token": token, "Content-Type": "application/json"}
        conn.request(method, path, body="{}" if method == "POST" else None, headers=headers)
        return conn.getresponse()

    try:
        assert request("GET", "/", f"evil.example:{port}").status == 421
        assert request("GET", "/api/state", f"127.0.0.1:{port}").status == 403
        assert request("POST", "/api/login", f"localhost:{port}", "bad").status == 403
        ok = request("GET", "/api/state", f"127.0.0.1:{port}", app.token)
        assert ok.status == 200
        state = json.loads(ok.read())
        assert state["logged_in"] is False
        assert state["settings"]["jump_host"] == "login.example.edu"  # defaults reach the form
        assert "password" not in json.dumps(state)
    finally:
        httpd.shutdown()


def test_login_requires_nodes(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(server, "data_dir", lambda: tmp_path)
    monkeypatch.setattr(server, "_bundled_defaults", lambda: {})
    app = server.App()
    code, payload = app.login({"jump_host": "h", "username": "u", "password": "p", "nodes": " "})
    assert code == 400 and "节点" in payload["error"]
