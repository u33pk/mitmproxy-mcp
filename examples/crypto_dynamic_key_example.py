"""Example CryptoHandler: dynamic key delivered by a login response.

Scenario:
1. POST /auth/login returns JSON containing an AES key.
2. All other endpoints use that AES key (CBC, key from login) for request/response bodies.

The handler extracts the key from the login response and keeps it in `self.context`
for subsequent flows.
"""

import json

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

from mitmproxy_mcp.crypto import CryptoHandler, CryptoResult


class DynamicKeyHandler(CryptoHandler):
    id = "example-dynamic-aes"
    name = "Dynamic AES key from login response"
    filter = "~u api.example.com"

    def _pad(self, data: bytes) -> bytes:
        pad_len = 16 - len(data) % 16
        return data + bytes([pad_len] * pad_len)

    def _unpad(self, data: bytes) -> bytes:
        return data[: -data[-1]]

    def _aes(self, data: bytes, key: bytes, iv: bytes, decrypt: bool) -> bytes:
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        if decrypt:
            decryptor = cipher.decryptor()
            return self._unpad(decryptor.update(data) + decryptor.finalize())
        encryptor = cipher.encryptor()
        return encryptor.update(self._pad(data)) + encryptor.finalize()

    def decrypt_response(self, flow):
        if flow.response is None:
            return None

        # Login endpoint returns the key in plaintext JSON.
        if "/auth/login" in flow.request.path:
            try:
                data = json.loads(flow.response.text or "{}")
                self.context["aes_key"] = data["key"].encode("utf-8")
                self.context["aes_iv"] = bytes.fromhex(data["iv"])
            except Exception as e:
                return CryptoResult(error=f"Failed to extract key: {e}")
            # Login body itself is not encrypted in this example.
            return CryptoResult(body=flow.response.raw_content)

        key = self.context.get("aes_key")
        iv = self.context.get("aes_iv")
        if not key or not iv:
            return CryptoResult(error="AES key not available yet; authenticate first")

        raw = flow.response.raw_content or b""
        try:
            plain = self._aes(raw, key, iv, decrypt=True)
        except Exception as e:
            return CryptoResult(error=f"AES decrypt failed: {e}")
        return CryptoResult(body=plain)

    def encrypt_request(self, flow, plaintext):
        key = self.context.get("aes_key")
        iv = self.context.get("aes_iv")
        if not key or not iv:
            return CryptoResult(error="AES key not available yet; authenticate first")
        try:
            cipher = self._aes(plaintext, key, iv, decrypt=False)
        except Exception as e:
            return CryptoResult(error=f"AES encrypt failed: {e}")
        return CryptoResult(body=cipher, headers={"Content-Length": str(len(cipher))})

    def decrypt_request(self, flow):
        key = self.context.get("aes_key")
        iv = self.context.get("aes_iv")
        if not key or not iv:
            return CryptoResult(error="AES key not available yet; authenticate first")
        raw = flow.request.raw_content or b""
        try:
            plain = self._aes(raw, key, iv, decrypt=True)
        except Exception as e:
            return CryptoResult(error=f"AES decrypt failed: {e}")
        return CryptoResult(body=plain)
