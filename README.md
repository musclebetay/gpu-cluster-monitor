# Cluster Monitor

A small desktop app that shows who is using which GPU on a cluster you reach over SSH:
per-node GPU memory and utilisation, the owner and command line of every GPU process,
CPU load, RAM and (optionally) disk usage. One row per node, one tile per GPU, nodes with
the most free cards first.

It is built for shared research clusters where compute nodes sit behind a login (jump) host
and you only have a normal user account.

- **No server-side install.** Each node runs a short read-only probe over SSH
  (`nvidia-smi`, `ps`, `free`, `df`, `/proc`). Nothing is executed on the jump host;
  it only forwards SSH connections to the nodes.
- **Password or key login.** The password stays in memory and is never written to disk.
- **The password only goes to verified hosts.** An unknown host key stops the connection
  before authentication and is shown as a fingerprint for you to confirm; a changed host key
  is refused outright.
- **No retry storms.** A node that refuses your login is not retried until you log in again,
  so the app does not look like a brute-force attempt to `fail2ban` or account lockout rules.
- **Local only.** The dashboard is served on `127.0.0.1` with a per-launch token and a
  `Host` header check, and is shown in a native window (pywebview).

The user interface is currently in Chinese.

## Download (Windows)

Grab `ClusterMonitor.exe` from the [Releases](../../releases) page. Each release lists the
SHA256 of the exe; check it with `Get-FileHash ClusterMonitor.exe` in PowerShell.

The exe is not code-signed, so SmartScreen will warn on first launch
("More info" → "Run anyway"). It needs the Microsoft Edge WebView2 runtime, which ships with
Windows 10/11.

## First run

1. Open the app and expand **高级设置** (advanced settings).
2. Fill in the jump host and port, the nodes to watch (comma separated; ranges such as
   `node1-20` are expanded) and, optionally, disk mount points such as `/home, /scratch`.
3. Enter your username and password and log in.
4. The first connection to each host shows its SHA256 host-key fingerprint. Compare it with
   the fingerprint your administrator publishes (or `ssh-keyscan` output from a machine you
   trust) before clicking **确认指纹并登录** / **信任**.

Everything except the password is remembered in `settings.json`, and confirmed host keys in
`known_hosts`, both in the per-user data directory:

| OS | Data directory |
|---|---|
| Windows | `%APPDATA%\ClusterMonitor` |
| macOS | `~/Library/Application Support/ClusterMonitor` |
| Linux | `~/.config/cluster_monitor` |

The log file `cluster_monitor.log` is written there when the app runs without a console.

## Site builds: pre-filled settings and pinned host keys

To hand the app to colleagues with everything pre-filled, add a `defaults/` directory before
building:

```
defaults/
├── config.json     # {"jump_host": "...", "jump_port": 22, "nodes": ["node1", ...], "disks": ["/home"]}
└── known_hosts     # OpenSSH known_hosts lines for the jump host and nodes
```

Keys in `defaults/known_hosts` are pinned: they are checked before the user's own
`known_hosts` and cannot be overridden from the app. Copy them from a `known_hosts` file you
already trust rather than scanning them fresh. Keep a site build in a private fork, since
`defaults/` describes your internal network. The CI workflow bundles `defaults/` automatically
when it exists.

## Development

```bash
uv venv .venv --python 3.12
uv pip install --python .venv/bin/python -r requirements.txt pytest
.venv/bin/python -m pytest -q tests
.venv/bin/python run.py              # native window
.venv/bin/python run.py --browser    # default browser instead
```

| Path | Purpose |
|---|---|
| `cluster_monitor/probe.py` | Read-only probe script run on each node, and its parser |
| `cluster_monitor/ssh_pool.py` | Persistent SSH connections through the jump host (paramiko) and host-key policy |
| `cluster_monitor/server.py` | Local HTTP API, per-node polling threads, settings |
| `cluster_monitor/app.py` | Entry point: starts the server and opens the window |
| `static/index.html` | Login screen and dashboard |

### Release builds

GitHub Actions builds the Windows exe with PyInstaller, runs the unit tests and a self-test of
the built exe on every push, and publishes the exe with its SHA256 when a `v*` tag is pushed.
Actions are pinned to commit SHAs and dependencies are installed from the hash-locked
`requirements-windows.txt`. To update dependencies, edit `requirements-build.in` and run:

```bash
uv pip compile requirements-build.in --python-platform x86_64-pc-windows-msvc \
  --python-version 3.12 --generate-hashes -o requirements-windows.txt
```

## License

MIT
