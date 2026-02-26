#!/usr/bin/env python3
"""Compatibility wrapper for renamed Cloudflare checker.

Use domain-cloudflare-check.py directly for new automation.
"""

from __future__ import annotations

import runpy
from pathlib import Path

if __name__ == "__main__":
    target = Path(__file__).with_name("domain-cloudflare-check.py")
    runpy.run_path(str(target), run_name="__main__")
