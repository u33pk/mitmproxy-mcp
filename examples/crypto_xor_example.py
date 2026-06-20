"""Example CryptoHandler: simple XOR cipher.

This demonstrates the minimum interface needed to transparently decrypt and
encrypt traffic. Load it with:

    crypt_ctl(cmd="load", script_path="examples/crypto_xor_example.py")
"""

from mitmproxy_mcp.crypto import CryptoHandler, CryptoResult


class XorHandler(CryptoHandler):
    id = "example-xor"
    name = "Example XOR handler"
    filter = "~u api.example.com"  # only flows matching this mitmproxy filter

    def __init__(self):
        super().__init__()
        self.key = b"secret"

    def _xor(self, data: bytes) -> bytes:
        return bytes(b ^ self.key[i % len(self.key)] for i, b in enumerate(data))

    def decrypt_request(self, flow):
        raw = flow.request.raw_content or b""
        return CryptoResult(body=self._xor(raw))

    def encrypt_request(self, flow, plaintext):
        return CryptoResult(body=self._xor(plaintext))

    def decrypt_response(self, flow):
        if flow.response is None:
            return None
        raw = flow.response.raw_content or b""
        return CryptoResult(body=self._xor(raw))

    def encrypt_response(self, flow, plaintext):
        return CryptoResult(body=self._xor(plaintext))
