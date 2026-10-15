"""Persistent SSH connections: one to the jump host, one per compute node through it.

Nothing is executed on the jump host; it only forwards TCP (direct-tcpip) to the
nodes. Passwords live in memory only.

Host keys are never trusted silently, because password authentication hands the
password to whichever server answers:
- keys shipped with the app (``defaults/known_hosts``) are pinned and always win;
- keys the user confirmed in the app are kept in the per-user known_hosts file;
- an unknown key aborts the connection before authentication (``UnknownHostKey``);
- a key that differs from a pinned or confirmed one aborts it too
  (``paramiko.BadHostKeyException``) and cannot be confirmed from the app.
"""

import base64
import hashlib
import logging
import threading
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Optional

import paramiko

logger = logging.getLogger(__name__)

CONNECT_TIMEOUT = 10
# nvidia-smi on idle cards without persistence mode can take ~30 s per call.
EXEC_TIMEOUT = 120


def fingerprint(key: paramiko.PKey) -> str:
    """OpenSSH-style SHA256 fingerprint, e.g. ``SHA256:0AFR+...``."""
    digest = hashlib.sha256(key.asbytes()).digest()
    return "SHA256:" + base64.b64encode(digest).decode().rstrip("=")


class UnknownHostKey(paramiko.SSHException):
    """The server presented a key that is neither pinned nor confirmed."""

    def __init__(self, hostname: str, key: paramiko.PKey) -> None:
        self.hostname = hostname
        self.key = key
        self.fingerprint = fingerprint(key)
        super().__init__(f"unknown host key for {hostname}: {self.fingerprint}")


class LoginRequired(paramiko.SSHException):
    """The jump host refused the stored credentials; stop and ask the user again."""


class _RejectUnknown(paramiko.MissingHostKeyPolicy):
    def missing_host_key(self, client: paramiko.SSHClient, hostname: str, key: paramiko.PKey) -> None:
        raise UnknownHostKey(hostname, key)


@dataclass(frozen=True)
class Credentials:
    """Login settings for the jump host and the nodes (same account on both)."""

    jump_host: str
    jump_port: int
    username: str
    password: Optional[str] = None
    key_file: Optional[str] = None

    @property
    def jump_key_name(self) -> str:
        """Name the jump host is stored under in known_hosts files."""
        if self.jump_port == 22:
            return self.jump_host
        return f"[{self.jump_host}]:{self.jump_port}"

    def auth_kwargs(self) -> Dict:
        kwargs: Dict = {
            "username": self.username,
            "timeout": CONNECT_TIMEOUT,
            "banner_timeout": CONNECT_TIMEOUT,
            "auth_timeout": CONNECT_TIMEOUT,
            "allow_agent": False,
            "look_for_keys": False,
        }
        if self.password:
            kwargs["password"] = self.password
        if self.key_file:
            kwargs["key_filename"] = self.key_file
        return kwargs


class SshPool:
    """Thread-safe pool of SSH clients keyed by node name."""

    def __init__(self, creds: Credentials, pinned_hosts: Path, known_hosts: Path) -> None:
        self._creds = creds
        self._pinned_hosts = pinned_hosts
        self._known_hosts = known_hosts
        self._known_hosts.parent.mkdir(parents=True, exist_ok=True)
        self._known_hosts.touch(exist_ok=True)
        self._lock = threading.Lock()
        # Serialises jump (re)connects so a dropped jump host is not logged into once per node.
        self._jump_lock = threading.Lock()
        self._jump: Optional[paramiko.SSHClient] = None
        self._nodes: Dict[str, paramiko.SSHClient] = {}
        self.login_required = False

    def _new_client(self) -> paramiko.SSHClient:
        client = paramiko.SSHClient()
        if self._pinned_hosts.exists():
            # "System" keys are checked first and never written back.
            client.load_system_host_keys(str(self._pinned_hosts))
        with self._lock:
            client.load_host_keys(str(self._known_hosts))
        client.set_missing_host_key_policy(_RejectUnknown())
        return client

    def trust(self, hostname: str, key: paramiko.PKey) -> None:
        """Record a host key the user confirmed."""
        with self._lock:
            keys = paramiko.HostKeys(str(self._known_hosts))
            keys.add(hostname, key.get_name(), key)
            keys.save(str(self._known_hosts))
        logger.info("Trusted host key for %s: %s", hostname, fingerprint(key))

    def connect_jump(self) -> None:
        """(Re)connect the jump host; raises paramiko/socket errors to the caller."""
        client = self._new_client()
        try:
            client.connect(self._creds.jump_host, port=self._creds.jump_port, **self._creds.auth_kwargs())
        except (paramiko.SSHException, OSError, EOFError):
            client.close()
            raise
        transport = client.get_transport()
        if transport is not None:
            transport.set_keepalive(30)
        with self._lock:
            old, self._jump = self._jump, client
        if old is not None:
            old.close()
        logger.info("Connected to jump host %s:%d", self._creds.jump_host, self._creds.jump_port)

    def _jump_transport(self) -> paramiko.Transport:
        with self._jump_lock:
            if self.login_required:
                raise LoginRequired("jump host needs a new login")
            with self._lock:
                client = self._jump
            transport = client.get_transport() if client else None
            if transport is None or not transport.is_active():
                try:
                    self.connect_jump()
                except (paramiko.AuthenticationException, paramiko.BadHostKeyException, UnknownHostKey) as exc:
                    # Never retry a refused login automatically: repeated failures look like
                    # brute force and can lock the account.
                    self.login_required = True
                    raise LoginRequired(str(exc)) from exc
                with self._lock:
                    transport = self._jump.get_transport() if self._jump else None
            if transport is None:
                raise paramiko.SSHException("jump host transport unavailable")
            return transport

    def _node_client(self, node: str) -> paramiko.SSHClient:
        with self._lock:
            client = self._nodes.get(node)
        transport = client.get_transport() if client else None
        if client is not None and transport is not None and transport.is_active():
            return client
        channel = self._jump_transport().open_channel(
            "direct-tcpip", (node, 22), ("127.0.0.1", 0), timeout=CONNECT_TIMEOUT
        )
        client = self._new_client()
        try:
            client.connect(node, sock=channel, **self._creds.auth_kwargs())
        except (paramiko.SSHException, OSError, EOFError):
            client.close()
            raise
        with self._lock:
            self._nodes[node] = client
        return client

    def run(self, node: str, script: str) -> str:
        """Run a bash script on a node via stdin and return its stdout."""
        try:
            client = self._node_client(node)
            stdin, stdout, _stderr = client.exec_command("bash -s", timeout=EXEC_TIMEOUT)
            stdin.write(script)
            stdin.channel.shutdown_write()
            return stdout.read().decode("utf-8", errors="replace")
        except (paramiko.SSHException, OSError, EOFError):
            self.drop(node)
            raise

    def drop(self, node: str) -> None:
        with self._lock:
            client = self._nodes.pop(node, None)
        if client is not None:
            client.close()

    def close(self) -> None:
        with self._lock:
            clients = list(self._nodes.values()) + ([self._jump] if self._jump else [])
            self._nodes.clear()
            self._jump = None
        for client in clients:
            client.close()
