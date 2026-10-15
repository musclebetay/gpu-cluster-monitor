"""PyInstaller entry script (a package module cannot be the frozen entry directly)."""

import sys

from cluster_monitor.app import main

if __name__ == "__main__":
    sys.exit(main())
