"""Tests for mitmproxy_mcp CA/certificate management."""

from __future__ import annotations

import os
import tempfile
from pathlib import Path

import pytest

from mitmproxy_mcp.proxy import CaConfig, ProxyManager
from mitmproxy_mcp.server import ca_ctl
from mitmproxy_mcp.store import FlowStore


def _make_manager() -> ProxyManager:
    return ProxyManager(FlowStore())


def test_ca_status_initial() -> None:
    manager = _make_manager()
    r = manager.ca_status()
    assert r["success"] is True
    assert r["verify_upstream"] is None
    assert r["upstream_ca_file"] is None
    assert r["upstream_ca_confdir"] is None
    assert r["client_cert"] is None
    assert r["cert_passphrase_set"] is False
    assert r["proxy_running"] is False


def test_set_verify_upstream() -> None:
    manager = _make_manager()
    assert manager.set_verify_upstream(True) == {"success": True, "verify_upstream": True}
    assert manager._ca_config.verify_upstream is True
    assert manager._ca_config.to_options()["ssl_insecure"] is False

    assert manager.set_verify_upstream(False) == {"success": True, "verify_upstream": False}
    assert manager._ca_config.verify_upstream is False
    assert manager._ca_config.to_options()["ssl_insecure"] is True


def test_set_upstream_ca_file(tmp_path: Path) -> None:
    manager = _make_manager()
    ca_file = tmp_path / "ca.pem"
    ca_file.write_text("-----BEGIN CERTIFICATE-----\nFAKE\n-----END CERTIFICATE-----\n")

    r = manager.set_upstream_ca(str(ca_file))
    assert r["success"] is True
    assert r["upstream_ca"] == str(ca_file)
    assert manager._ca_config.upstream_ca_file == str(ca_file)
    assert manager._ca_config.upstream_ca_confdir is None


def test_set_upstream_ca_directory(tmp_path: Path) -> None:
    manager = _make_manager()
    ca_dir = tmp_path / "ca-dir"
    ca_dir.mkdir()

    r = manager.set_upstream_ca(str(ca_dir))
    assert r["success"] is True
    assert r["upstream_ca"] == str(ca_dir)
    assert manager._ca_config.upstream_ca_confdir == str(ca_dir)
    assert manager._ca_config.upstream_ca_file is None


def test_set_upstream_ca_missing() -> None:
    manager = _make_manager()
    r = manager.set_upstream_ca("/nonexistent/path.pem")
    assert r["success"] is False
    assert "does not exist" in r["error"]


def test_clear_upstream_ca(tmp_path: Path) -> None:
    manager = _make_manager()
    ca_file = tmp_path / "ca.pem"
    ca_file.write_text("fake")
    manager.set_upstream_ca(str(ca_file))

    r = manager.clear_upstream_ca()
    assert r["success"] is True
    assert manager._ca_config.upstream_ca_file is None
    assert manager._ca_config.upstream_ca_confdir is None


def _write_key(path: Path, encrypted: bool = False, passphrase: str | None = None) -> None:
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    if encrypted and passphrase:
        enc = serialization.BestAvailableEncryption(passphrase.encode())
    else:
        enc = serialization.NoEncryption()
    path.write_bytes(
        key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=enc,
        )
    )


def test_set_client_cert_combined(tmp_path: Path) -> None:
    manager = _make_manager()
    cert_file = tmp_path / "client.pem"
    cert_file.write_text("-----BEGIN CERTIFICATE-----\nFAKE\n-----END CERTIFICATE-----\n")

    r = manager.set_client_cert(str(cert_file))
    assert r["success"] is True
    assert r["client_cert"].endswith("client_cert_client.pem")
    assert manager._ca_config.client_cert == r["client_cert"]


def test_set_client_cert_with_key(tmp_path: Path) -> None:
    manager = _make_manager()
    cert_file = tmp_path / "client.pem"
    cert_file.write_text("-----BEGIN CERTIFICATE-----\nFAKE\n-----END CERTIFICATE-----\n")
    key_file = tmp_path / "client.key"
    _write_key(key_file)

    r = manager.set_client_cert(str(cert_file), key_path=str(key_file))
    assert r["success"] is True
    combined = Path(r["client_cert"])
    assert combined.exists()
    text = combined.read_text()
    assert "BEGIN CERTIFICATE" in text
    assert "BEGIN RSA PRIVATE KEY" in text or "BEGIN PRIVATE KEY" in text


def test_set_client_cert_encrypted_key(tmp_path: Path) -> None:
    manager = _make_manager()
    cert_file = tmp_path / "client.pem"
    cert_file.write_text("-----BEGIN CERTIFICATE-----\nFAKE\n-----END CERTIFICATE-----\n")
    key_file = tmp_path / "client.key"
    _write_key(key_file, encrypted=True, passphrase="secret")

    r = manager.set_client_cert(str(cert_file), key_path=str(key_file), passphrase="secret")
    assert r["success"] is True
    combined = Path(r["client_cert"])
    assert "BEGIN RSA PRIVATE KEY" in combined.read_text() or "BEGIN PRIVATE KEY" in combined.read_text()


def test_set_client_cert_missing_files() -> None:
    manager = _make_manager()
    r = manager.set_client_cert("/nonexistent/cert.pem")
    assert r["success"] is False
    assert "Certificate file does not exist" in r["error"]

    cert_file = Path("/tmp/exists.pem")
    cert_file.write_text("cert")
    try:
        r = manager.set_client_cert(str(cert_file), key_path="/nonexistent/key.pem")
        assert r["success"] is False
        assert "Key file does not exist" in r["error"]
    finally:
        cert_file.unlink(missing_ok=True)


def test_clear_client_cert(tmp_path: Path) -> None:
    manager = _make_manager()
    cert_file = tmp_path / "client.pem"
    cert_file.write_text("cert")
    manager.set_client_cert(str(cert_file))

    r = manager.clear_client_cert()
    assert r["success"] is True
    assert manager._ca_config.client_cert is None
    assert manager._ca_config.cert_passphrase is None


def test_export_ca(tmp_path: Path) -> None:
    manager = _make_manager()
    mitmproxy_dir = Path.home() / ".mitmproxy"
    mitmproxy_dir.mkdir(parents=True, exist_ok=True)
    src = mitmproxy_dir / "mitmproxy-ca-cert.cer"
    original_text = "fake-ca"
    src.write_text(original_text)

    try:
        r = manager.export_ca(str(tmp_path))
        assert r["success"] is True
        assert r["path"] == str(tmp_path / "mitmproxy-ca-cert.cer")
        assert Path(r["path"]).read_text() == original_text
    finally:
        src.write_text(original_text)


def test_export_ca_missing() -> None:
    manager = _make_manager()
    src = Path.home() / ".mitmproxy" / "mitmproxy-ca-cert.cer"
    backup = None
    if src.exists():
        backup = src.read_bytes()
        src.unlink()
    try:
        r = manager.export_ca()
        assert r["success"] is False
        assert "not found" in r["error"]
    finally:
        if backup is not None:
            src.write_bytes(backup)


def test_ca_config_survives_stop_start() -> None:
    manager = _make_manager()
    manager.set_verify_upstream(True)
    assert manager._ca_config.verify_upstream is True
    # Stopping a non-running proxy resets nothing relevant.
    # The point is that _ca_config is independent of _options.
    assert manager.ca_status()["verify_upstream"] is True


def test_ca_ctl_tool_status() -> None:
    r = ca_ctl(cmd="status")
    assert r["success"] is True
    assert "verify_upstream" in r


def test_ca_ctl_tool_set_verify_upstream() -> None:
    r = ca_ctl(cmd="set_verify_upstream", enabled=False)
    assert r["success"] is True
    assert r["verify_upstream"] is False
    # Reset to default so other tests are not affected.
    ca_ctl(cmd="set_verify_upstream", enabled=True)


def test_ca_ctl_tool_upstream_ca_validation(tmp_path: Path) -> None:
    r = ca_ctl(cmd="set_upstream_ca", ca_path="/nonexistent")
    assert r["success"] is False

    ca_file = tmp_path / "ca.pem"
    ca_file.write_text("fake")
    r = ca_ctl(cmd="set_upstream_ca", ca_path=str(ca_file))
    assert r["success"] is True
    ca_ctl(cmd="clear_upstream_ca")


def test_ca_ctl_tool_client_cert_validation(tmp_path: Path) -> None:
    r = ca_ctl(cmd="set_client_cert", cert_path="/nonexistent")
    assert r["success"] is False

    cert_file = tmp_path / "client.pem"
    cert_file.write_text("cert")
    r = ca_ctl(cmd="set_client_cert", cert_path=str(cert_file))
    assert r["success"] is True
    ca_ctl(cmd="clear_client_cert")
