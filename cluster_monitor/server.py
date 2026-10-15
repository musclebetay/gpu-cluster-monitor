"""Local HTTP server: login API, polling threads and the dashboard page.

Binds to 127.0.0.1 only. Every /api/ call must carry the per-launch token embedded
in the served page, and every request must name 127.0.0.1/localhost in its Host
header, so other web pages (including DNS-rebinding ones) cannot drive the API.
"""

import json
import logging
import os
import secrets
import sys
import threading
import time
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Dict, List, Optional, Tuple

import paramiko

from .probe import build_script, format_list, parse_list, parse_node
from .ssh_pool import Credentials, LoginRequired, SshPool, UnknownHostKey, fingerprint

logger = logging.getLogger(__name__)

POLL_INTERVAL = 10.0
# Unreachable nodes (network errors only) are retried this often.
RETRY_INTERVAL = 120.0
# Failure kinds that must not be retried automatically.
BLOCKING_KINDS = ("auth", "hostkey_unknown", "hostkey_changed")


def resource_dir() -> Path:
    """Directory holding bundled files (PyInstaller unpacks to sys._MEIPASS)."""
    return Path(getattr(sys, "_MEIPASS", Path(__file__).resolve().parent.parent))


def data_dir() -> Path:
    """Per-user directory for settings and confirmed host keys."""
    if sys.platform == "win32":
        base = Path(os.environ.get("APPDATA", Path.home()))
        return base / "ClusterMonitor"
    if sys.platform == "darwin":
        return Path.home() / "Library" / "Application Support" / "ClusterMonitor"
    return Path.home() / ".config" / "cluster_monitor"


def _bundled_defaults() -> Dict:
    """Optional site defaults shipped next to the code (``defaults/config.json``)."""
    path = resource_dir() / "defaults" / "config.json"
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return {}
    except (OSError, ValueError) as exc:
        logger.warning("Ignoring unreadable bundled defaults %s: %s", path, exc)
        return {}


@dataclass(frozen=True)
class Settings:
    """Non-secret settings remembered between launches (never the password)."""

    jump_host: str = ""
    jump_port: int = 22
    username: str = ""
    key_file: str = ""
    nodes: Tuple[str, ...] = ()
    disks: Tuple[str, ...] = ()
    interval: float = POLL_INTERVAL

    @classmethod
    def load(cls, path: Path) -> "Settings":
        """Bundled defaults, overridden by the user's saved settings."""
        raw = _bundled_defaults()
        try:
            raw.update({k: v for k, v in json.loads(path.read_text(encoding="utf-8")).items() if v})
        except FileNotFoundError:
            pass
        except (OSError, ValueError) as exc:
            logger.warning("Ignoring unreadable settings %s: %s", path, exc)
        return cls(
            jump_host=str(raw.get("jump_host", "")),
            jump_port=int(raw.get("jump_port", 22)),
            username=str(raw.get("username", "")),
            key_file=str(raw.get("key_file", "")),
            nodes=tuple(raw.get("nodes") or ()),
            disks=tuple(raw.get("disks") or ()),
            interval=float(raw.get("interval", POLL_INTERVAL)),
        )

    def save(self, path: Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            "jump_host": self.jump_host,
            "jump_port": self.jump_port,
            "username": self.username,
            "key_file": self.key_file,
            "interval": self.interval,
        }
        defaults = _bundled_defaults()
        # Lists are stored only when customised, so a new release can update the defaults.
        if list(self.nodes) != list(defaults.get("nodes") or []):
            payload["nodes"] = list(self.nodes)
        if list(self.disks) != list(defaults.get("disks") or []):
            payload["disks"] = list(self.disks)
        path.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")


def _failure(node: str, started: float, kind: str, error: str, **extra: str) -> Dict:
    return {"node": node, "ok": False, "kind": kind, "error": error, "ts": started, **extra}


class Collector:
    """One polling thread per node; keeps the latest record for each."""

    def __init__(
        self, pool: SshPool, nodes: Tuple[str, ...], interval: float, disks: Tuple[str, ...] = ()
    ) -> None:
        self._pool = pool
        self._script = build_script(disks)
        self._nodes = nodes
        self._interval = interval
        self._stop = threading.Event()
        self._wake = {n: threading.Event() for n in nodes}
        self._lock = threading.Lock()
        self._pending_keys: Dict[str, paramiko.PKey] = {}
        self._records: Dict[str, Dict] = {
            n: {"node": n, "ok": False, "pending": True, "error": "连接中…", "ts": 0.0} for n in nodes
        }

    def start(self) -> None:
        for node in self._nodes:
            threading.Thread(target=self._loop, args=(node,), daemon=True, name=f"poll-{node}").start()

    def stop(self) -> None:
        self._stop.set()
        for event in self._wake.values():
            event.set()

    def snapshot(self) -> List[Dict]:
        with self._lock:
            return [self._records[n] for n in self._nodes]

    def trust(self, node: str, fp: str) -> bool:
        """Trust the key a node presented, if it is still the one the user saw."""
        with self._lock:
            key = self._pending_keys.get(node)
        if key is None or fingerprint(key) != fp:
            return False
        self._pool.trust(node, key)
        with self._lock:
            self._pending_keys.pop(node, None)
            self._records[node] = {"node": node, "ok": False, "pending": True, "error": "连接中…", "ts": 0.0}
        self._wake[node].set()
        return True

    def _poll(self, node: str) -> Dict:
        started = time.time()
        try:
            text = self._pool.run(node, self._script)
        except LoginRequired:
            return _failure(node, started, "login", "跳板机拒绝了登录，请重新登录")
        except UnknownHostKey as exc:
            with self._lock:
                self._pending_keys[node] = exc.key
            return _failure(node, started, "hostkey_unknown", "新节点，主机密钥未确认，尚未发送密码",
                            fingerprint=exc.fingerprint)
        except paramiko.BadHostKeyException as exc:
            return _failure(node, started, "hostkey_changed",
                            f"主机密钥与记录不一致（现在是 {fingerprint(exc.key)}），已拒绝连接")
        except paramiko.AuthenticationException:
            return _failure(node, started, "auth", "认证失败（该节点不接受此账号），不再自动重试")
        except paramiko.ChannelException as exc:
            reason = "跳板机不允许转发到该节点" if exc.code == 1 else "节点不在线或不可达"
            return _failure(node, started, "unreachable", f"{reason}（{exc.text}）")
        except paramiko.SSHException as exc:
            if "Unable to open channel" in str(exc):
                return _failure(node, started, "unreachable", "节点不在线或不可达（打开通道超时）")
            return _failure(node, started, "error", f"SSH 错误：{exc}")
        except (OSError, EOFError) as exc:
            return _failure(node, started, "error", f"{type(exc).__name__}: {exc}")
        if "@@gpu" not in text:
            return _failure(node, started, "error", "探测脚本没有输出")
        try:
            record = parse_node(text)
        except (ValueError, IndexError) as exc:
            logger.error("%s: could not parse probe output: %s", node, exc)
            return _failure(node, started, "error", f"解析失败: {exc}")
        return {"node": node, "ok": True, "ts": started, "latency": time.time() - started, **record}

    def _loop(self, node: str) -> None:
        while not self._stop.is_set():
            t0 = time.time()
            record = self._poll(node)
            if self._stop.is_set():
                return
            with self._lock:
                previous = self._records[node]
                if not record["ok"] and previous.get("ok") and record["kind"] in ("unreachable", "error"):
                    # Keep the last good reading visible, flagged as stale.
                    record = {**previous, "stale": True, "error": record["error"]}
                self._records[node] = record
            kind = record.get("kind")
            if kind == "login":
                return
            if kind in BLOCKING_KINDS:
                # Wait for the user (trust button or a new login), never retry on our own.
                self._wake[node].wait()
                self._wake[node].clear()
                continue
            wait = self._interval if record["ok"] or record.get("stale") else RETRY_INTERVAL
            self._stop.wait(max(0.0, wait - (time.time() - t0)))


class App:
    """Holds the login session; at most one collector runs at a time."""

    def __init__(self) -> None:
        self.token = secrets.token_urlsafe(16)
        self.settings_path = data_dir() / "settings.json"
        self.known_hosts = data_dir() / "known_hosts"
        self.pinned_hosts = resource_dir() / "defaults" / "known_hosts"
        self.settings = Settings.load(self.settings_path)
        self.message = ""
        self._lock = threading.Lock()
        self._pool: Optional[SshPool] = None
        self._collector: Optional[Collector] = None

    def login(self, body: Dict) -> Tuple[int, Dict]:
        try:
            port = int(body.get("jump_port") or 22)
        except ValueError:
            return 400, {"error": "端口必须是数字"}
        settings = Settings(
            jump_host=str(body.get("jump_host", "")).strip(),
            jump_port=port,
            username=str(body.get("username", "")).strip(),
            key_file=str(body.get("key_file", "")).strip(),
            nodes=tuple(parse_list(str(body["nodes"]))) if "nodes" in body else self.settings.nodes,
            disks=tuple(parse_list(str(body["disks"]))) if "disks" in body else self.settings.disks,
            interval=self.settings.interval,
        )
        password = str(body.get("password", ""))
        if not settings.jump_host or not settings.username:
            return 400, {"error": "请填写跳板机地址和用户名"}
        if not password and not settings.key_file:
            return 400, {"error": "请输入密码"}
        if not settings.nodes:
            return 400, {"error": "请在高级设置里填写要监控的节点"}
        creds = Credentials(
            settings.jump_host, settings.jump_port, settings.username,
            password=password or None, key_file=settings.key_file or None,
        )
        pool = SshPool(creds, self.pinned_hosts, self.known_hosts)
        try:
            try:
                pool.connect_jump()
            except UnknownHostKey as exc:
                if body.get("trust_fingerprint") != exc.fingerprint:
                    return 409, {"confirm_fingerprint": exc.fingerprint, "host": creds.jump_key_name}
                pool.trust(exc.hostname, exc.key)
                pool.connect_jump()
        except paramiko.BadHostKeyException as exc:
            return 401, {"error": f"跳板机的主机密钥与记录不一致（现在是 {fingerprint(exc.key)}），"
                                  "已拒绝连接，密码没有发送。请先向管理员确认服务器没有被冒充。"}
        except paramiko.AuthenticationException:
            return 401, {"error": "用户名或密码错误"}
        except (paramiko.SSHException, OSError, EOFError) as exc:
            return 502, {"error": f"连不上跳板机：{exc}（检查 VPN / 地址 / 端口）"}
        self.logout()
        collector = Collector(pool, settings.nodes, settings.interval, settings.disks)
        with self._lock:
            self._pool, self._collector, self.settings, self.message = pool, collector, settings, ""
        settings.save(self.settings_path)
        collector.start()
        return 200, {"ok": True}

    def trust(self, body: Dict) -> Tuple[int, Dict]:
        with self._lock:
            collector = self._collector
        if collector is None:
            return 409, {"error": "未登录"}
        if collector.trust(str(body.get("node", "")), str(body.get("fingerprint", ""))):
            return 200, {"ok": True}
        return 409, {"error": "该节点的密钥已经变化，请刷新后重新确认"}

    def logout(self, message: str = "") -> None:
        with self._lock:
            pool, collector = self._pool, self._collector
            self._pool = self._collector = None
            self.message = message
        if collector is not None:
            collector.stop()
        if pool is not None:
            pool.close()

    def state(self) -> Dict:
        with self._lock:
            pool, collector = self._pool, self._collector
        if pool is not None and pool.login_required:
            self.logout("跳板机拒绝了之前的登录（可能改了密码或会话过期），请重新登录。")
            collector = None
        s = self.settings
        return {
            "logged_in": collector is not None,
            "message": self.message,
            "now": time.time(),
            "interval": s.interval,
            "username": s.username,
            "settings": {"jump_host": s.jump_host, "jump_port": s.jump_port,
                         "username": s.username, "key_file": s.key_file,
                         "nodes": format_list(s.nodes), "disks": ", ".join(s.disks)},
            "nodes": collector.snapshot() if collector else [],
        }


def make_handler(app: App) -> type:
    """Build a request handler bound to the app."""
    page = (resource_dir() / "static" / "index.html").read_text(encoding="utf-8")
    page_bytes = page.replace("__API_TOKEN__", app.token).encode("utf-8")

    class Handler(BaseHTTPRequestHandler):
        def _send(self, code: int, body: bytes, ctype: str) -> None:
            self.send_response(code)
            self.send_header("Content-Type", ctype)
            self.send_header("Cache-Control", "no-store")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def _json(self, code: int, payload: Dict) -> None:
            self._send(code, json.dumps(payload, ensure_ascii=False).encode("utf-8"), "application/json")

        def _local_host(self) -> bool:
            host = self.headers.get("Host", "").rsplit(":", 1)[0].strip("[]").lower()
            if host in ("127.0.0.1", "localhost"):
                return True
            self.send_error(421, "Misdirected Request")
            return False

        def _authorized(self) -> bool:
            if secrets.compare_digest(self.headers.get("X-Token", ""), app.token):
                return True
            self._json(403, {"error": "forbidden"})
            return False

        def do_GET(self) -> None:  # noqa: N802 (http.server API)
            if not self._local_host():
                return
            if self.path in ("/", "/index.html"):
                self._send(200, page_bytes, "text/html; charset=utf-8")
            elif self.path.startswith("/api/state"):
                if self._authorized():
                    self._json(200, app.state())
            else:
                self.send_error(404)

        def do_POST(self) -> None:  # noqa: N802 (http.server API)
            if not self._local_host() or not self._authorized():
                return
            length = int(self.headers.get("Content-Length") or 0)
            try:
                body = json.loads(self.rfile.read(length) or b"{}")
            except ValueError:
                self._json(400, {"error": "bad json"})
                return
            if self.path == "/api/login":
                code, payload = app.login(body)
                self._json(code, payload)
            elif self.path == "/api/trust":
                code, payload = app.trust(body)
                self._json(code, payload)
            elif self.path == "/api/logout":
                app.logout()
                self._json(200, {"ok": True})
            else:
                self.send_error(404)

        def log_message(self, fmt: str, *args: object) -> None:
            logger.debug(fmt, *args)

    return Handler


def start_server(app: App, port: int) -> ThreadingHTTPServer:
    """Start the HTTP server in a daemon thread; port 0 picks a free port."""
    server = ThreadingHTTPServer(("127.0.0.1", port), make_handler(app))
    threading.Thread(target=server.serve_forever, daemon=True, name="http").start()
    return server
