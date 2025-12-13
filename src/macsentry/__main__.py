"""Entry point for python -m macsentry."""
from __future__ import annotations

import sys

from .macos_security_audit import main

if __name__ == "__main__":
    sys.exit(main())
