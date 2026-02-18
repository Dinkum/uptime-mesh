from __future__ import annotations

import argparse
import base64
import json
import sys
import time
from pathlib import Path
from typing import Any, Dict, Optional
from urllib import error, request

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.hazmat.primitives.asymmetric.padding import PKCS1v15
from cryptography.x509.oid import NameOID

from app.identity import heartbeat_signing_message
from app.security import SESSION_COOKIE_NAME


def _api_request(
    *,
    base_url: str,
    path: str,
    method: str = "GET",
    json_body: Optional[Dict[str, Any]] = None,
    session_token: Optional[str] = None,
) -> Any:
    url = base_url.rstrip("/") + path
    headers: Dict[str, str] = {"Accept": "application/json"}
    data: Optional[bytes] = None

    if json_body is not None:
        data = json.dumps(json_body).encode("utf-8")
        headers["Content-Type"] = "application/json"

    if session_token:
        headers["Cookie"] = f"{SESSION_COOKIE_NAME}={session_token}"

    req = request.Request(url=url, method=method.upper(), data=data, headers=headers)
    try:
        with request.urlopen(req, timeout=15) as response:
            body = response.read().decode("utf-8")
            return json.loads(body) if body else {}
    except error.HTTPError as exc:
        payload = exc.read().decode("utf-8")
        detail = payload
        try:
            parsed = json.loads(payload)
            if isinstance(parsed, dict) and "detail" in parsed:
                detail = str(parsed["detail"])
        except json.JSONDecodeError:
            pass
        raise RuntimeError(f"HTTP {exc.code}: {detail}") from exc


def _login(base_url: str, username: str, password: str) -> str:
    result = _api_request(
        base_url=base_url,
        path="/auth/token",
        method="POST",
        json_body={"username": username, "password": password},
    )
    token = result.get("session_token")
    if not isinstance(token, str) or not token:
        raise RuntimeError("Authentication failed: no session token returned.")
    return token


def _print_json(data: Dict[str, Any]) -> None:
    print(json.dumps(data, indent=2, sort_keys=True))


def _parse_labels(items: list[str]) -> Dict[str, str]:
    labels: Dict[str, str] = {}
    for item in items:
        if "=" not in item:
            raise RuntimeError(f"Invalid --label value '{item}'. Expected key=value")
        key, value = item.split("=", 1)
        key = key.strip()
        if not key:
            raise RuntimeError("Label key cannot be empty")
        labels[key] = value.strip()
    return labels


def _identity_dir(root: str, node_id: str) -> Path:
    return Path(root) / node_id


def _generate_key_and_csr(node_id: str) -> tuple[str, str]:
    key = ec.generate_private_key(ec.SECP256R1())
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, node_id)])
    csr = x509.CertificateSigningRequestBuilder().subject_name(subject).sign(key, hashes.SHA256())

    key_pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode("utf-8")
    csr_pem = csr.public_bytes(serialization.Encoding.PEM).decode("utf-8")
    return key_pem, csr_pem


def _write_identity_artifacts(
    *,
    identity_root: str,
    node_id: str,
    key_pem: str,
    cert_pem: str,
    ca_pem: str,
    lease_token: str,
) -> Dict[str, str]:
    path = _identity_dir(identity_root, node_id)
    path.mkdir(parents=True, exist_ok=True)

    key_path = path / "node.key"
    cert_path = path / "node.crt"
    ca_path = path / "ca.crt"
    lease_path = path / "lease.token"

    key_path.write_text(key_pem)
    cert_path.write_text(cert_pem)
    ca_path.write_text(ca_pem)
    lease_path.write_text(lease_token)
    key_path.chmod(0o600)

    return {
        "key_path": str(key_path),
        "cert_path": str(cert_path),
        "ca_path": str(ca_path),
        "lease_token_path": str(lease_path),
    }


def _load_private_key(key_path: Path) -> ec.EllipticCurvePrivateKey | rsa.RSAPrivateKey:
    key_raw = key_path.read_bytes()
    private_key = serialization.load_pem_private_key(key_raw, password=None)
    if isinstance(private_key, ec.EllipticCurvePrivateKey | rsa.RSAPrivateKey):
        return private_key
    raise RuntimeError("Unsupported key type for heartbeat signing")


def _sign(private_key: ec.EllipticCurvePrivateKey | rsa.RSAPrivateKey, message: bytes) -> str:
    if isinstance(private_key, ec.EllipticCurvePrivateKey):
        signature = private_key.sign(message, ec.ECDSA(hashes.SHA256()))
    else:
        signature = private_key.sign(message, PKCS1v15(), hashes.SHA256())
    return base64.b64encode(signature).decode("ascii")


def cmd_bootstrap(args: argparse.Namespace) -> int:
    session_token = _login(args.api_url, args.username, args.password)
    response = _api_request(
        base_url=args.api_url,
        path="/cluster/bootstrap",
        method="POST",
        json_body={
            "core_token_ttl_seconds": args.core_ttl,
            "worker_token_ttl_seconds": args.worker_ttl,
        },
        session_token=session_token,
    )
    _print_json(response)
    return 0


def cmd_create_token(args: argparse.Namespace) -> int:
    session_token = _login(args.api_url, args.username, args.password)
    response = _api_request(
        base_url=args.api_url,
        path="/cluster/join-tokens",
        method="POST",
        json_body={"role": args.role, "ttl_seconds": args.ttl},
        session_token=session_token,
    )
    _print_json(response)
    return 0


def cmd_join(args: argparse.Namespace) -> int:
    key_pem, csr_pem = _generate_key_and_csr(args.node_id)
    response = _api_request(
        base_url=args.api_url,
        path="/cluster/join",
        method="POST",
        json_body={
            "token": args.token,
            "node_id": args.node_id,
            "name": args.name,
            "role": args.role,
            "mesh_ip": args.mesh_ip,
            "api_endpoint": args.api_endpoint,
            "etcd_peer_url": args.etcd_peer_url,
            "labels": _parse_labels(args.label),
            "status": {},
            "lease_ttl_seconds": args.lease_ttl,
            "csr_pem": csr_pem,
        },
    )
    artifact_paths = _write_identity_artifacts(
        identity_root=args.identity_dir,
        node_id=args.node_id,
        key_pem=key_pem,
        cert_pem=str(response["node_cert_pem"]),
        ca_pem=str(response["ca_cert_pem"]),
        lease_token=str(response["lease_token"]),
    )
    response["identity_paths"] = artifact_paths
    _print_json(response)
    return 0


def cmd_heartbeat(args: argparse.Namespace) -> int:
    status_patch: Dict[str, Any] = {}
    if args.status_json:
        parsed = json.loads(args.status_json)
        if not isinstance(parsed, dict):
            raise RuntimeError("--status-json must be a JSON object")
        status_patch = parsed

    path = _identity_dir(args.identity_dir, args.node_id)
    key_path = path / "node.key"
    lease_path = path / "lease.token"
    if not key_path.exists():
        raise RuntimeError(f"Missing node private key: {key_path}")

    lease_token = args.lease_token or lease_path.read_text().strip()
    if not lease_token:
        raise RuntimeError("Lease token is empty.")

    signed_at = int(time.time())
    message = heartbeat_signing_message(
        node_id=args.node_id,
        lease_token=lease_token,
        signed_at=signed_at,
        ttl_seconds=args.ttl,
        status_patch=status_patch,
    )
    private_key = _load_private_key(key_path)
    signature = _sign(private_key, message)

    response = _api_request(
        base_url=args.api_url,
        path="/cluster/heartbeat",
        method="POST",
        json_body={
            "node_id": args.node_id,
            "lease_token": lease_token,
            "ttl_seconds": args.ttl,
            "status_patch": status_patch,
            "signed_at": signed_at,
            "signature": signature,
        },
    )
    _print_json(response)
    return 0


def cmd_nodes_status(args: argparse.Namespace) -> int:
    session_token = _login(args.api_url, args.username, args.password)
    rows_any = _api_request(
        base_url=args.api_url,
        path="/cluster/leases",
        method="GET",
        session_token=session_token,
    )
    if not isinstance(rows_any, list):
        raise RuntimeError("Unexpected response for /cluster/leases")
    rows: list[Dict[str, Any]] = []
    for item in rows_any:
        if isinstance(item, dict):
            rows.append(item)
    print("NODE\tROLE\tLEASE\tHEARTBEAT\tEXPIRES")
    for row in rows:
        roles = ",".join(row.get("roles", []))
        print(
            f"{row.get('node_id', '-')}\t{roles}\t{row.get('lease_state', '-')}\t"
            f"{row.get('heartbeat_at', '-')}\t{row.get('lease_expires_at', '-')}"
        )
    return 0


def cmd_etcd_status(args: argparse.Namespace) -> int:
    session_token = _login(args.api_url, args.username, args.password)
    result = _api_request(
        base_url=args.api_url,
        path="/etcd/status",
        method="GET",
        session_token=session_token,
    )
    if not isinstance(result, dict):
        raise RuntimeError("Unexpected response for /etcd/status")
    _print_json(result)
    return 0


def cmd_etcd_members(args: argparse.Namespace) -> int:
    session_token = _login(args.api_url, args.username, args.password)
    result = _api_request(
        base_url=args.api_url,
        path="/etcd/members",
        method="GET",
        session_token=session_token,
    )
    if not isinstance(result, list):
        raise RuntimeError("Unexpected response for /etcd/members")
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


def cmd_snapshot_run(args: argparse.Namespace) -> int:
    session_token = _login(args.api_url, args.username, args.password)
    body: Dict[str, Any] = {}
    if args.id:
        body["id"] = args.id
    if args.requested_by:
        body["requested_by"] = args.requested_by
    result = _api_request(
        base_url=args.api_url,
        path="/etcd/snapshots",
        method="POST",
        json_body=body,
        session_token=session_token,
    )
    if not isinstance(result, dict):
        raise RuntimeError("Unexpected response for snapshot run")
    _print_json(result)
    return 0


def cmd_snapshot_list(args: argparse.Namespace) -> int:
    session_token = _login(args.api_url, args.username, args.password)
    result = _api_request(
        base_url=args.api_url,
        path="/etcd/snapshots",
        method="GET",
        session_token=session_token,
    )
    if not isinstance(result, list):
        raise RuntimeError("Unexpected response for /etcd/snapshots")
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


def cmd_snapshot_restore(args: argparse.Namespace) -> int:
    session_token = _login(args.api_url, args.username, args.password)
    result = _api_request(
        base_url=args.api_url,
        path=f"/etcd/snapshots/{args.snapshot_id}/restore",
        method="POST",
        json_body={},
        session_token=session_token,
    )
    if not isinstance(result, dict):
        raise RuntimeError("Unexpected response for snapshot restore")
    _print_json(result)
    return 0


def cmd_support_bundle_run(args: argparse.Namespace) -> int:
    session_token = _login(args.api_url, args.username, args.password)
    body: Dict[str, Any] = {}
    if args.id:
        body["id"] = args.id
    if args.requested_by:
        body["requested_by"] = args.requested_by
    result = _api_request(
        base_url=args.api_url,
        path="/support-bundles",
        method="POST",
        json_body=body,
        session_token=session_token,
    )
    if not isinstance(result, dict):
        raise RuntimeError("Unexpected response for support bundle run")
    _print_json(result)
    return 0


def cmd_support_bundle_list(args: argparse.Namespace) -> int:
    session_token = _login(args.api_url, args.username, args.password)
    result = _api_request(
        base_url=args.api_url,
        path="/support-bundles",
        method="GET",
        session_token=session_token,
    )
    if not isinstance(result, list):
        raise RuntimeError("Unexpected response for /support-bundles")
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="uptimemesh", description="UptimeMesh ASCII-first CLI")
    parser.add_argument("--api-url", default="http://127.0.0.1:8000")

    sub = parser.add_subparsers(dest="command", required=True)

    bootstrap = sub.add_parser("bootstrap", help="Bootstrap cluster and issue initial join tokens")
    bootstrap.add_argument("--username", default="admin")
    bootstrap.add_argument("--password", default="uptime")
    bootstrap.add_argument("--core-ttl", type=int, default=1800)
    bootstrap.add_argument("--worker-ttl", type=int, default=1800)
    bootstrap.set_defaults(func=cmd_bootstrap)

    create_token = sub.add_parser("create-token", help="Create a join token")
    create_token.add_argument("--username", default="admin")
    create_token.add_argument("--password", default="uptime")
    create_token.add_argument("--role", choices=["core", "worker", "gateway"], required=True)
    create_token.add_argument("--ttl", type=int, default=1800)
    create_token.set_defaults(func=cmd_create_token)

    join = sub.add_parser("join", help="Join node with a one-time token and CSR-based identity")
    join.add_argument("--token", required=True)
    join.add_argument("--node-id", required=True)
    join.add_argument("--name", required=True)
    join.add_argument("--role", choices=["core", "worker", "gateway"], required=True)
    join.add_argument("--mesh-ip")
    join.add_argument("--api-endpoint")
    join.add_argument("--etcd-peer-url")
    join.add_argument("--lease-ttl", type=int, default=45)
    join.add_argument("--identity-dir", default="data/identities")
    join.add_argument("--label", action="append", default=[])
    join.set_defaults(func=cmd_join)

    heartbeat = sub.add_parser("heartbeat", help="Send signed node heartbeat")
    heartbeat.add_argument("--node-id", required=True)
    heartbeat.add_argument("--identity-dir", default="data/identities")
    heartbeat.add_argument("--lease-token")
    heartbeat.add_argument("--ttl", type=int, default=45)
    heartbeat.add_argument("--status-json", default="{}")
    heartbeat.set_defaults(func=cmd_heartbeat)

    nodes_status = sub.add_parser("nodes-status", help="Show lease status for nodes")
    nodes_status.add_argument("--username", default="admin")
    nodes_status.add_argument("--password", default="uptime")
    nodes_status.set_defaults(func=cmd_nodes_status)

    etcd_status = sub.add_parser("etcd-status", help="Show etcd endpoint health")
    etcd_status.add_argument("--username", default="admin")
    etcd_status.add_argument("--password", default="uptime")
    etcd_status.set_defaults(func=cmd_etcd_status)

    etcd_members = sub.add_parser("etcd-members", help="List etcd members")
    etcd_members.add_argument("--username", default="admin")
    etcd_members.add_argument("--password", default="uptime")
    etcd_members.set_defaults(func=cmd_etcd_members)

    snapshot_run = sub.add_parser("snapshot-run", help="Run etcd snapshot now")
    snapshot_run.add_argument("--username", default="admin")
    snapshot_run.add_argument("--password", default="uptime")
    snapshot_run.add_argument("--id")
    snapshot_run.add_argument("--requested-by")
    snapshot_run.set_defaults(func=cmd_snapshot_run)

    snapshot_list = sub.add_parser("snapshot-list", help="List etcd snapshots")
    snapshot_list.add_argument("--username", default="admin")
    snapshot_list.add_argument("--password", default="uptime")
    snapshot_list.set_defaults(func=cmd_snapshot_list)

    snapshot_restore = sub.add_parser("snapshot-restore", help="Restore etcd snapshot")
    snapshot_restore.add_argument("snapshot_id")
    snapshot_restore.add_argument("--username", default="admin")
    snapshot_restore.add_argument("--password", default="uptime")
    snapshot_restore.set_defaults(func=cmd_snapshot_restore)

    support_bundle_run = sub.add_parser("support-bundle-run", help="Generate support bundle")
    support_bundle_run.add_argument("--username", default="admin")
    support_bundle_run.add_argument("--password", default="uptime")
    support_bundle_run.add_argument("--id")
    support_bundle_run.add_argument("--requested-by")
    support_bundle_run.set_defaults(func=cmd_support_bundle_run)

    support_bundle_list = sub.add_parser("support-bundle-list", help="List support bundles")
    support_bundle_list.add_argument("--username", default="admin")
    support_bundle_list.add_argument("--password", default="uptime")
    support_bundle_list.set_defaults(func=cmd_support_bundle_list)

    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()
    try:
        exit_code = args.func(args)
    except Exception as exc:  # noqa: BLE001
        print(f"error: {exc}", file=sys.stderr)
        raise SystemExit(1) from exc
    raise SystemExit(exit_code)


if __name__ == "__main__":
    main()
