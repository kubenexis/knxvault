"""HTTP client for KNXVault REST API."""

from __future__ import annotations

import os
from typing import Any

import urllib.error
import urllib.request
import json


class Client:
    def __init__(self, base_url: str | None = None, token: str | None = None) -> None:
        self.base_url = (base_url or os.getenv("KNXVAULT_ADDR") or "http://localhost:8200").rstrip("/")
        self.token = token or os.getenv("KNXVAULT_TOKEN") or ""

    def health(self) -> dict[str, Any]:
        return self._request("GET", "/health", auth=False)

    def kv_put(self, path: str, data: dict[str, Any]) -> None:
        self._request("POST", f"/secrets/kv/{path.lstrip('/')}", {"data": data})

    def kv_get(self, path: str) -> dict[str, Any]:
        return self._request("GET", f"/secrets/kv/{path.lstrip('/')}")

    def _request(self, method: str, path: str, body: dict[str, Any] | None = None, *, auth: bool = True) -> Any:
        payload = None if body is None else json.dumps(body).encode()
        req = urllib.request.Request(self.base_url + path, data=payload, method=method)
        req.add_header("Content-Type", "application/json")
        if auth and self.token:
            req.add_header("Authorization", f"Bearer {self.token}")
        try:
            with urllib.request.urlopen(req, timeout=30) as resp:
                raw = resp.read()
        except urllib.error.HTTPError as exc:
            raise RuntimeError(exc.read().decode() or str(exc)) from exc
        if not raw:
            return {}
        return json.loads(raw)