from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, Optional

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.hazmat.primitives.asymmetric.padding import PKCS1v15
from cryptography.x509.oid import NameOID


def _b64url_encode(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def _b64url_decode(value: str) -> bytes:
    padding = "=" * ((4 - len(value) % 4) % 4)
    return base64.urlsafe_b64decode(value + padding)


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def ensure_cluster_ca(pki_dir: str) -> tuple[str, str]:
    path = Path(pki_dir)
    path.mkdir(parents=True, exist_ok=True)
    key_path = path / "cluster-ca.key"
    cert_path = path / "cluster-ca.crt"

    if key_path.exists() and cert_path.exists():
        return key_path.read_text(), cert_path.read_text()

    key = ec.generate_private_key(ec.SECP256R1())
    subject = x509.Name(
        [
            x509.NameAttribute(NameOID.COMMON_NAME, "UptimeMesh Cluster CA"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "UptimeMesh"),
        ]
    )
    now = _utcnow()
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(days=3650))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
        .sign(private_key=key, algorithm=hashes.SHA256())
    )

    key_pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode("utf-8")
    cert_pem = cert.public_bytes(serialization.Encoding.PEM).decode("utf-8")
    key_path.write_text(key_pem)
    cert_path.write_text(cert_pem)
    os.chmod(key_path, 0o600)
    return key_pem, cert_pem


def sign_node_csr(
    *,
    pki_dir: str,
    csr_pem: str,
    node_id: str,
    validity_days: int,
) -> tuple[str, str, str, datetime]:
    ca_key_pem, ca_cert_pem = ensure_cluster_ca(pki_dir)
    ca_key = serialization.load_pem_private_key(ca_key_pem.encode("utf-8"), password=None)
    if not isinstance(ca_key, ec.EllipticCurvePrivateKey | rsa.RSAPrivateKey):
        raise ValueError("Unsupported CA private key type.")
    ca_cert = x509.load_pem_x509_certificate(ca_cert_pem.encode("utf-8"))

    csr = x509.load_pem_x509_csr(csr_pem.encode("utf-8"))
    cn_attrs = csr.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
    if not cn_attrs or cn_attrs[0].value != node_id:
        raise ValueError("CSR common name must match node_id.")

    now = _utcnow()
    builder = (
        x509.CertificateBuilder()
        .subject_name(csr.subject)
        .issuer_name(ca_cert.subject)
        .public_key(csr.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(days=validity_days))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
    )

    try:
        san_ext = csr.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        builder = builder.add_extension(san_ext.value, critical=False)
    except x509.ExtensionNotFound:
        pass

    cert = builder.sign(private_key=ca_key, algorithm=hashes.SHA256())
    cert_pem = cert.public_bytes(serialization.Encoding.PEM).decode("utf-8")
    fingerprint = cert.fingerprint(hashes.SHA256()).hex()
    not_after = getattr(cert, "not_valid_after_utc", None)
    if not_after is None:
        not_after = cert.not_valid_after
        if not_after.tzinfo is None:
            not_after = not_after.replace(tzinfo=timezone.utc)
        else:
            not_after = not_after.astimezone(timezone.utc)
    return cert_pem, ca_cert_pem, fingerprint, not_after


def create_lease_token(
    *,
    node_id: str,
    identity_fingerprint: str,
    secret_key: str,
    ttl_seconds: int,
    now: Optional[int] = None,
) -> str:
    issued_at = now if now is not None else int(time.time())
    payload = {
        "n": node_id,
        "fp": identity_fingerprint,
        "iat": issued_at,
        "exp": issued_at + ttl_seconds,
    }
    payload_json = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")
    payload_b64 = _b64url_encode(payload_json)
    signature = hmac.new(secret_key.encode("utf-8"), payload_b64.encode("ascii"), hashlib.sha256).digest()
    return f"{payload_b64}.{_b64url_encode(signature)}"


def decode_lease_token(token: str, secret_key: str, *, now: Optional[int] = None) -> Optional[Dict[str, Any]]:
    try:
        payload_b64, signature_b64 = token.split(".", 1)
    except ValueError:
        return None
    expected_signature = hmac.new(
        secret_key.encode("utf-8"),
        payload_b64.encode("ascii"),
        hashlib.sha256,
    ).digest()
    try:
        actual_signature = _b64url_decode(signature_b64)
    except (ValueError, TypeError):
        return None
    if not hmac.compare_digest(actual_signature, expected_signature):
        return None
    try:
        payload = json.loads(_b64url_decode(payload_b64))
    except (ValueError, TypeError, json.JSONDecodeError):
        return None

    expires_at = payload.get("exp")
    node_id = payload.get("n")
    fingerprint = payload.get("fp")
    if not isinstance(expires_at, int) or not isinstance(node_id, str) or not isinstance(fingerprint, str):
        return None
    current = now if now is not None else int(time.time())
    if expires_at < current:
        return None
    return payload


def heartbeat_signing_message(
    *,
    node_id: str,
    lease_token: str,
    signed_at: int,
    ttl_seconds: int,
    status_patch: Dict[str, Any],
) -> bytes:
    status_json = json.dumps(status_patch, sort_keys=True, separators=(",", ":"))
    raw = f"{node_id}\n{lease_token}\n{signed_at}\n{ttl_seconds}\n{status_json}"
    return raw.encode("utf-8")


def verify_heartbeat_signature(*, cert_pem: str, message: bytes, signature_b64: str) -> bool:
    try:
        cert = x509.load_pem_x509_certificate(cert_pem.encode("utf-8"))
        signature = base64.b64decode(signature_b64.encode("utf-8"), validate=True)
    except Exception:
        return False

    public_key = cert.public_key()
    try:
        if isinstance(public_key, rsa.RSAPublicKey):
            public_key.verify(signature, message, PKCS1v15(), hashes.SHA256())
        elif isinstance(public_key, ec.EllipticCurvePublicKey):
            public_key.verify(signature, message, ec.ECDSA(hashes.SHA256()))
        else:
            return False
    except InvalidSignature:
        return False
    return True
