#!/usr/bin/env python3
"""W40-04: Python client smoke example against dev server."""
import os
import urllib.request

addr = os.environ.get("KNXVAULT_ADDR", "http://127.0.0.1:8200")
with urllib.request.urlopen(f"{addr}/health", timeout=5) as resp:
    print(resp.read().decode())