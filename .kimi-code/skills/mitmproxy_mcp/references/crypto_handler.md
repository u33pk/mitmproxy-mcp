# Writing CryptoHandler scripts for `crypt_ctl`

This reference explains how to write Python scripts that `crypt_ctl` can load to transparently decrypt and encrypt HTTP/WebSocket traffic.

## When to use

Use a `CryptoHandler` when the target application encrypts request/response bodies in user space (e.g. front-end JavaScript, mobile apps, proprietary protocols). Once loaded, `http_ctl get` shows decrypted plaintext and `flow_action(action="update", decrypted_request_body=...)` + `flow_action(action="replay")` automatically re-encrypts.

## Minimal script

```python
from mitmproxy_mcp.crypto import CryptoHandler, CryptoResult

class XorHandler(CryptoHandler):
    id = "my-xor"
    name = "My XOR handler"
    filter = "~u api.example.com"

    def __init__(self):
        super().__init__()
        self.key = b"secret"

    def _xor(self, data: bytes) -> bytes:
        return bytes(b ^ self.key[i % len(self.key)] for i, b in enumerate(data))

    def decrypt_request(self, flow):
        return CryptoResult(body=self._xor(flow.request.raw_content or b""))

    def encrypt_request(self, flow, plaintext):
        return CryptoResult(body=self._xor(plaintext))

    def decrypt_response(self, flow):
        if flow.response is None:
            return None
        return CryptoResult(body=self._xor(flow.response.raw_content or b""))

    def encrypt_response(self, flow, plaintext):
        return CryptoResult(body=self._xor(plaintext))
```

Save as `my_crypto.py` and load with:

```python
crypt_ctl(cmd="load", script_path="/path/to/my_crypto.py")
```

## `CryptoHandler` interface

### Class attributes

| Attribute | Required | Description |
|-----------|----------|-------------|
| `id` | yes | Unique script identifier. Used by `unload`/`reload`/`status`. |
| `name` | no | Human-readable name. |
| `filter` | no | mitmproxy `flowfilter` expression. When set, the handler only processes matching flows. |
| `priority` | no | Integer, higher values are evaluated first. Default `0`. |

### Injected attributes

| Attribute | Type | Description |
|-----------|------|-------------|
| `self.store` | `FlowStore` | All captured flows. Use it to inspect previous traffic (e.g. find a handshake response). |
| `self.context` | `dict` | Per-handler persistent dict. Use it to cache keys across requests. |
| `self._logger` | `logging.Logger` | Logger for the handler. |

### Lifecycle hooks

```python
def on_load(self, store):
    """Called when the script is loaded."""
    pass

def on_unload(self):
    """Called when the script is unloaded."""
    pass
```

### Matching

```python
def match(self, flow: http.HTTPFlow) -> bool:
    """Return True to process this flow."""
    return True
```

Override for custom logic beyond `filter`. The default uses `filter` if set.

### HTTP methods

```python
def decrypt_request(self, flow: http.HTTPFlow) -> CryptoResult | None:
    """Decrypt outgoing request before LLM sees it."""

def encrypt_request(self, flow: http.HTTPFlow, plaintext: bytes) -> CryptoResult | None:
    """Encrypt modified plaintext before sending to server."""

def decrypt_response(self, flow: http.HTTPFlow) -> CryptoResult | None:
    """Decrypt incoming response before LLM sees it."""

def encrypt_response(self, flow: http.HTTPFlow, plaintext: bytes) -> CryptoResult | None:
    """Encrypt modified plaintext before returning to client."""
```

### WebSocket methods

```python
def decrypt_websocket_message(self, flow: http.HTTPFlow, msg) -> CryptoResult | None:
    """Decrypt a captured WebSocket message."""

def encrypt_websocket_message(self, flow: http.HTTPFlow, msg, plaintext: bytes) -> CryptoResult | None:
    """Encrypt a modified WebSocket message before forwarding."""
```

## `CryptoResult`

Return `None` to leave the object unchanged. Otherwise return:

```python
CryptoResult(
    body=b"...",                 # replace body
    headers={"X-Foo": "bar"},    # add or overwrite headers
    remove_headers=["X-Old"],    # remove headers
    metadata={"key_id": "abc"},  # attach metadata to flow/message
    drop=False,                  # True to drop the request/response/message
    error="...",                 # reported in crypt_ctl status, skips transformation
)
```

## Algorithm recipes

### XOR with a fixed key

```python
def _xor(self, data: bytes, key: bytes) -> bytes:
    return bytes(b ^ key[i % len(key)] for i, b in enumerate(data))
```

### AES-CBC with a fixed key/IV

```python
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

def _decrypt_aes_cbc(self, data: bytes, key: bytes, iv: bytes) -> bytes:
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    padded = decryptor.update(data) + decryptor.finalize()
    return padded[:-padded[-1]]  # PKCS7 unpad

def _encrypt_aes_cbc(self, data: bytes, key: bytes, iv: bytes) -> bytes:
    pad_len = 16 - len(data) % 16
    padded = data + bytes([pad_len] * pad_len)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    return encryptor.update(padded) + encryptor.finalize()
```

### AES-GCM

```python
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

def _decrypt_aes_gcm(self, data: bytes, key: bytes, nonce: bytes, aad: bytes | None = None) -> bytes:
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(nonce, data, aad)

def _encrypt_aes_gcm(self, data: bytes, key: bytes, nonce: bytes, aad: bytes | None = None) -> bytes:
    aesgcm = AESGCM(key)
    return aesgcm.encrypt(nonce, data, aad)
```

### ChaCha20-Poly1305

```python
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

def _decrypt_chacha(self, data: bytes, key: bytes, nonce: bytes, aad: bytes | None = None) -> bytes:
    chacha = ChaCha20Poly1305(key)
    return chacha.decrypt(nonce, data, aad)
```

### Base64 wrapping

```python
import base64

CryptoResult(body=base64.b64decode(flow.request.raw_content))
```

### JSON payload transformation

When the encrypted data is embedded in JSON:

```python
import json

def decrypt_request(self, flow):
    payload = json.loads(flow.request.text or "{}")
    cipher = base64.b64decode(payload["data"])
    plain = self._decrypt(cipher)
    payload["data"] = plain.decode("utf-8")
    return CryptoResult(body=json.dumps(payload).encode("utf-8"))
```

### RSA (small payloads, common for key exchange)

```python
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding

def _load_private_key(self, path: str):
    with open(path, "rb") as f:
        return serialization.load_pem_private_key(f.read(), password=None)

def _decrypt_rsa(self, data: bytes) -> bytes:
    return self._private_key.decrypt(
        data,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )
```

### RC4 / ARC4

```python
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms
from cryptography.hazmat.backends import default_backend

def _rc4(self, data: bytes, key: bytes) -> bytes:
    cipher = Cipher(algorithms.ARC4(key), mode=None, backend=default_backend())
    return cipher.encryptor().update(data)
```

RC4 encryption and decryption are the same operation.

### Custom混淆 / byte shuffle

For proprietary transforms, implement the inverse operation in the decrypt methods:

```python
def _unshuffle(self, data: bytes) -> bytes:
    # Implement the reverse of the client-side shuffle
    return bytes(data[(i * 7) % len(data)] for i in range(len(data)))
```

## Dynamic key patterns

### Key delivered by a login response

```python
def decrypt_response(self, flow):
    if "/auth/login" in flow.request.path:
        data = json.loads(flow.response.text or "{}")
        self.context["key"] = base64.b64decode(data["session_key"])
        return CryptoResult(body=flow.response.raw_content)

    key = self.context.get("key")
    if not key:
        return CryptoResult(error="session key not available")
    return CryptoResult(body=self._decrypt(flow.response.raw_content, key))

def encrypt_request(self, flow, plaintext):
    key = self.context.get("key")
    if not key:
        return CryptoResult(error="session key not available")
    return CryptoResult(body=self._encrypt(plaintext, key))
```

### Derive key from a previous handshake flow

```python
def decrypt_request(self, flow):
    session_id = flow.request.headers.get("X-Session-Id")
    for sid, f in reversed(self.store.list()):
        if f.request.path == "/handshake" and f.metadata.get("session_id") == session_id:
            key = self._derive_key(f.response.raw_content)
            return CryptoResult(body=self._decrypt(flow.request.raw_content, key))
    return CryptoResult(error="handshake not found")
```

## Error handling

Never raise exceptions from handler methods. Instead return:

```python
return CryptoResult(error="reason")
```

The error appears in `crypt_ctl(cmd="status", script_id="...")` and is logged.

## Security warning

`crypt_ctl` executes the Python file you provide. Only load scripts from trusted sources. Avoid loading scripts from world-writable directories.

## Testing a handler

```python
from mitmproxy_mcp.utils import create_http_flow
from mitmproxy_mcp.crypto import CryptoAddon

addon = CryptoAddon()
# load your script...
flow = create_http_flow("POST", "http://api.example.com/api", body=b"cipher")
addon.request(flow)
print(flow.metadata["mitmproxy_mcp_decrypted_request"])
```
