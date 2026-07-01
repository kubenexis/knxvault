import os
import unittest
import urllib.error

from knxvault import Client


class PythonClientTest(unittest.TestCase):
    def test_health_offline(self):
        client = Client("http://127.0.0.1:1", "")
        with self.assertRaises(RuntimeError):
            client.health()

    def test_smoke(self):
        if os.getenv("KNXVAULT_SMOKE") != "1":
            self.skipTest("set KNXVAULT_SMOKE=1 for live smoke test")
        token = os.getenv("KNXVAULT_TOKEN")
        if not token:
            self.skipTest("KNXVAULT_TOKEN required")
        client = Client(os.getenv("KNXVAULT_ADDR"), token)
        client.health()
        client.kv_put("clients/smoke", {"ok": True})
        data = client.kv_get("clients/smoke")
        self.assertTrue(data.get("data", {}).get("ok"))


if __name__ == "__main__":
    unittest.main()