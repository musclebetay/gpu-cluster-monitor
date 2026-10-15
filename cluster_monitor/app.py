"""Entry point: start the local server and show the dashboard in a desktop window.

Usage:
    python -m cluster_monitor.app              # desktop window (pywebview)
    python -m cluster_monitor.app --browser    # default browser instead
    python -m cluster_monitor.app --serve-only # server only (development)
    python -m cluster_monitor.app --selftest   # import/parse check for CI, then exit
"""

import argparse
import logging
import sys
import threading
import webbrowser

from .probe import parse_node
from .server import App, Settings, data_dir, resource_dir, start_server

logger = logging.getLogger(__name__)

APP_TITLE = "集群监控"

_SAMPLE_OUTPUT = """@@nproc 48
@@load 8.89 8.60 8.36 2/549 22903
@@mem 257663 17000 231000
@@disk
/data 1863 1055
@@gpu
0, GPU-a, NVIDIA GeForce RTX 4090, 22328, 24564, 97, 66
1, GPU-b, NVIDIA GeForce RTX 4090, 0, 24564, 0, 40
@@apps
GPU-a, 35001, 22322
@@ps
35001 someone 01:02:03 python train.py
@@top
someone 760.5
"""


def selftest() -> int:
    """Check that bundled files, paramiko and the parser work inside the build."""
    import paramiko

    page = resource_dir() / "static" / "index.html"
    if "__API_TOKEN__" not in page.read_text(encoding="utf-8"):
        logger.error("index.html missing or malformed at %s", page)
        return 1
    defaults_dir = resource_dir() / "defaults"
    if defaults_dir.exists():
        # A site build must carry a usable default config and its pinned host keys.
        pinned = paramiko.HostKeys(str(defaults_dir / "known_hosts"))
        defaults = Settings.load(data_dir() / "__selftest_missing__.json")
        if not pinned.keys() or not defaults.jump_host or not defaults.nodes:
            logger.error("bundled defaults incomplete: %d pinned hosts, jump=%r", len(pinned.keys()), defaults.jump_host)
            return 1
    record = parse_node(_SAMPLE_OUTPUT)
    ok = (
        record["nproc"] == 48
        and record["gpus"][0]["procs"][0]["user"] == "someone"
        and record["gpus"][1]["procs"] == []
    )
    if not ok:
        logger.error("parser self-test failed: %s", record)
        return 1
    if "--with-webview" in sys.argv:
        import webview  # noqa: F401  (import check only)
    logger.info("selftest ok (data dir %s)", data_dir())
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=APP_TITLE)
    parser.add_argument("--browser", action="store_true", help="open in the default browser")
    parser.add_argument("--port", type=int, default=0, help="local port (0 = any free port)")
    parser.add_argument("--serve-only", action="store_true", help="only run the local server")
    parser.add_argument("--selftest", action="store_true")
    parser.add_argument("--with-webview", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--debug", action="store_true")
    args = parser.parse_args()
    log_kwargs = {}
    if sys.stderr is None:
        # Windowed PyInstaller build: no console, so log to a file in the data dir.
        data_dir().mkdir(parents=True, exist_ok=True)
        log_kwargs = {"filename": str(data_dir() / "cluster_monitor.log"), "encoding": "utf-8"}
    logging.basicConfig(
        level=logging.DEBUG if args.debug else logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
        **log_kwargs,
    )
    logging.getLogger("paramiko").setLevel(logging.CRITICAL)
    if args.selftest:
        return selftest()

    app = App()
    server = start_server(app, args.port)
    url = f"http://127.0.0.1:{server.server_address[1]}/"
    logger.info("Serving %s", url)

    if not args.browser and not args.serve_only:
        try:
            import webview
        except ImportError:
            logger.warning("pywebview not available, falling back to the browser")
        else:
            webview.create_window(APP_TITLE, url, width=1240, height=820, min_size=(420, 400))
            webview.start()
            app.logout()
            return 0

    if not args.serve_only:
        webbrowser.open(url)
    logger.info("Open %s in a browser; press Ctrl+C to quit", url)
    try:
        threading.Event().wait()
    except KeyboardInterrupt:
        pass
    app.logout()
    return 0


if __name__ == "__main__":
    sys.exit(main())
