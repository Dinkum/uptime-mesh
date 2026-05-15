from __future__ import annotations

import asyncio
import base64
import json
import re
import sys
import time
from pathlib import Path
from typing import Any
from urllib.parse import urlencode

from alembic import command
from alembic.config import Config
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

ROOT = Path(__file__).resolve().parents[1]


class ASGIResponse:
    def __init__(self, status_code: int, headers: list[tuple[bytes, bytes]], body: bytes) -> None:
        self.status_code = status_code
        self.headers = headers
        self.body = body

    @property
    def text(self) -> str:
        return self.body.decode("utf-8")

    def json(self) -> dict[str, Any]:
        payload = json.loads(self.body)
        assert isinstance(payload, dict)
        return payload

    def header(self, name: str) -> str:
        expected = name.lower().encode("ascii")
        for key, value in self.headers:
            if key.lower() == expected:
                return value.decode("latin-1")
        return ""


async def _asgi_request(
    app: Any,
    method: str,
    path: str,
    *,
    headers: dict[str, str] | None = None,
    json_body: dict[str, Any] | None = None,
    form_body: dict[str, str] | None = None,
) -> ASGIResponse:
    request_headers = [(b"host", b"testserver")]
    body = b""
    if json_body is not None:
        body = json.dumps(json_body).encode("utf-8")
        request_headers.append((b"content-type", b"application/json"))
    if form_body is not None:
        body = urlencode(form_body).encode("utf-8")
        request_headers.append((b"content-type", b"application/x-www-form-urlencoded"))
    for key, value in (headers or {}).items():
        request_headers.append((key.lower().encode("ascii"), value.encode("latin-1")))

    raw_path, _, raw_query = path.partition("?")
    scope = {
        "type": "http",
        "asgi": {"version": "3.0"},
        "http_version": "1.1",
        "method": method,
        "scheme": "http",
        "path": raw_path,
        "raw_path": raw_path.encode("ascii"),
        "query_string": raw_query.encode("ascii"),
        "headers": request_headers,
        "client": ("127.0.0.1", 12345),
        "server": ("testserver", 80),
    }
    sent_request = False
    response_status = 500
    response_headers: list[tuple[bytes, bytes]] = []
    response_body = bytearray()

    async def receive() -> dict[str, Any]:
        nonlocal sent_request
        if not sent_request:
            sent_request = True
            return {"type": "http.request", "body": body, "more_body": False}
        return {"type": "http.disconnect"}

    async def send(message: dict[str, Any]) -> None:
        nonlocal response_status, response_headers
        if message["type"] == "http.response.start":
            response_status = int(message["status"])
            response_headers = list(message.get("headers", []))
        elif message["type"] == "http.response.body":
            response_body.extend(message.get("body", b""))

    await app(scope, receive, send)
    return ASGIResponse(response_status, response_headers, bytes(response_body))


def _make_node_csr(node_id: str) -> tuple[str, ec.EllipticCurvePrivateKey]:
    key = ec.generate_private_key(ec.SECP256R1())
    csr = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, node_id)]))
        .sign(key, hashes.SHA256())
    )
    return csr.public_bytes(serialization.Encoding.PEM).decode("utf-8"), key


def _prepare_app(tmp_path: Path, monkeypatch: Any) -> tuple[Any, str]:
    database_path = tmp_path / "smoke.db"
    database_url = f"sqlite+aiosqlite:///{database_path}"
    monkeypatch.setenv("DATABASE_URL", database_url)
    monkeypatch.setenv("AUTH_SECRET_KEY", "test-auth-secret-key-with-enough-entropy")
    monkeypatch.setenv("CLUSTER_SIGNING_KEY", "test-cluster-signing-key-with-enough-entropy")
    monkeypatch.setenv("CLUSTER_PKI_DIR", str(tmp_path / "pki"))
    monkeypatch.setenv("SUPPORT_BUNDLE_DIR", str(tmp_path / "support-bundles"))
    monkeypatch.setenv("LOG_FILE", str(tmp_path / "app.log"))
    monkeypatch.setenv("MANAGED_CONFIG_PATH", str(tmp_path / "config.yaml"))
    monkeypatch.setenv("LXD_ENABLED", "false")

    for cache_owner in ("app.config", "app.dependencies"):
        module = sys.modules.get(cache_owner)
        if module is not None:
            for cache_name in ("get_settings", "get_engine", "get_sessionmaker"):
                cached = getattr(module, cache_name, None)
                if cached is not None and hasattr(cached, "cache_clear"):
                    cached.cache_clear()

    alembic_config = Config(str(ROOT / "alembic.ini"))
    alembic_config.set_main_option("script_location", str(ROOT / "migrations"))
    command.upgrade(alembic_config, "head")

    from app.dependencies import get_sessionmaker
    from app.services.auth import set_credentials

    async def seed_credentials() -> None:
        sessionmaker = get_sessionmaker(database_url)
        async with sessionmaker() as session:
            await set_credentials(session, username="admin", password="correct-horse-password")
            await session.commit()

    asyncio.run(seed_credentials())

    sys.modules.pop("app.main", None)
    from app.main import app

    return app, database_url


def test_release_smoke_login_create_join_heartbeat_gateway_and_support_bundle(
    tmp_path: Path,
    monkeypatch: Any,
) -> None:
    app, _ = _prepare_app(tmp_path, monkeypatch)

    async def scenario() -> None:
        login_page = await _asgi_request(app, "GET", "/auth/login")
        assert login_page.status_code == 200
        assert "Sign In" in login_page.text

        login = await _asgi_request(
            app,
            "POST",
            "/auth/login",
            form_body={
                "username": "admin",
                "password": "correct-horse-password",
                "next": "/ui",
            },
        )
        assert login.status_code == 303
        cookie = login.header("set-cookie").split(";", 1)[0]
        assert cookie.startswith("uptimemesh_session=")
        auth_headers = {"cookie": cookie}

        node = await _asgi_request(
            app,
            "POST",
            "/nodes",
            headers=auth_headers,
            json_body={
                "id": "node-a",
                "name": "Node A",
                "roles": ["backend_server"],
                "labels": {"region": "test"},
                "mesh_ip": "10.42.0.10",
                "status": {"capacity": 1},
                "api_endpoint": "http://10.42.0.10:8000",
            },
        )
        assert node.status_code == 201, node.text
        assert node.json()["name"] == "Node A"

        service = await _asgi_request(
            app,
            "POST",
            "/services",
            headers=auth_headers,
            json_body={
                "id": "svc-web",
                "name": "Web",
                "description": "Smoke service",
                "spec": {
                    "type": "container",
                    "container": {
                        "image": "ghcr.io/dinkum/smoke-web:1.0.0",
                        "port": 3000,
                        "healthcheck": {"path": "/health", "expected_status": 200},
                        "env": {"APP_ENV": "test"},
                    },
                    "gateway": {"enabled": True, "host": "web.example.test", "path": "/"},
                    "availability": {"protection": "survive_one_failure"},
                    "scheduling": {"desired_replicas": 2, "anti_affinity": True},
                },
            },
        )
        assert service.status_code == 201, service.text
        assert service.json()["name"] == "Web"
        assert service.json()["spec"]["runtime"]["kind"] == "docker"

        token_response = await _asgi_request(
            app,
            "POST",
            "/cluster/join-tokens",
            headers=auth_headers,
            json_body={"role": "backend_server", "ttl_seconds": 600},
        )
        assert token_response.status_code == 201, token_response.text
        join_token = token_response.json()["token"]

        csr_pem, key = _make_node_csr("node-b")
        join = await _asgi_request(
            app,
            "POST",
            "/cluster/join",
            json_body={
                "token": join_token,
                "node_id": "node-b",
                "name": "Node B",
                "role": "backend_server",
                "mesh_ip": "10.42.0.11",
                "api_endpoint": "http://10.42.0.11:8000",
                "labels": {"region": "test"},
                "status": {},
                "lease_ttl_seconds": 45,
                "csr_pem": csr_pem,
            },
        )
        assert join.status_code == 200, join.text
        lease_token = join.json()["lease_token"]

        from app.identity import heartbeat_signing_message

        status_patch = {"load": {"cpu": 0.1}, "health": "ok"}
        signed_at = int(time.time())
        message = heartbeat_signing_message(
            node_id="node-b",
            lease_token=lease_token,
            signed_at=signed_at,
            ttl_seconds=45,
            status_patch=status_patch,
        )
        signature = base64.b64encode(key.sign(message, ec.ECDSA(hashes.SHA256()))).decode("ascii")
        heartbeat = await _asgi_request(
            app,
            "POST",
            "/cluster/heartbeat",
            json_body={
                "node_id": "node-b",
                "lease_token": lease_token,
                "ttl_seconds": 45,
                "status_patch": status_patch,
                "signed_at": signed_at,
                "signature": signature,
            },
        )
        assert heartbeat.status_code == 200, heartbeat.text
        assert heartbeat.json()["lease_state"] == "alive"

        replica = await _asgi_request(
            app,
            "POST",
            "/replicas",
            headers=auth_headers,
            json_body={
                "id": "svc-web-node-b",
                "service_id": "svc-web",
                "node_id": "node-b",
                "desired_state": "running",
                "status": {"applied_generation": 1, "healthy": True},
            },
        )
        assert replica.status_code == 201, replica.text
        assert replica.json()["status"]["runtime_kind"] == "docker"
        assert replica.json()["status"]["docker_endpoint_port"] == 3000

        endpoint_health = await _asgi_request(
            app,
            "PATCH",
            "/endpoints/svc-web-node-b-http",
            headers=auth_headers,
            json_body={"healthy": True},
        )
        assert endpoint_health.status_code == 200, endpoint_health.text

        service_state = await _asgi_request(
            app,
            "GET",
            "/services/svc-web/state",
            headers=auth_headers,
        )
        assert service_state.status_code == 200, service_state.text
        assert service_state.json()["desired"]["runtime"] == "docker"
        assert service_state.json()["observed"]["healthy_endpoints"] == 1

        survivor_report = await _asgi_request(
            app,
            "GET",
            "/services/survivor/report",
            headers=auth_headers,
        )
        assert survivor_report.status_code == 200, survivor_report.text
        assert survivor_report.json()["at_risk"] == 1

        provider_summary = await _asgi_request(
            app,
            "GET",
            "/providers",
            headers=auth_headers,
        )
        assert provider_summary.status_code == 200, provider_summary.text
        assert any(
            row["provider"] == "cloudflare"
            and "dns.plan" in row["capabilities"]
            for row in provider_summary.json()["capabilities"]
        )

        survivor_page = await _asgi_request(
            app,
            "GET",
            "/ui/workloads?tab=survivor",
            headers=auth_headers,
        )
        assert survivor_page.status_code == 200, survivor_page.text
        assert "Survivor Tests" in survivor_page.text

        state_page = await _asgi_request(
            app,
            "GET",
            "/ui/workloads?tab=state",
            headers=auth_headers,
        )
        assert state_page.status_code == 200, state_page.text
        assert "Service State" in state_page.text

        providers_page = await _asgi_request(
            app,
            "GET",
            "/ui/settings?section=providers",
            headers=auth_headers,
        )
        assert providers_page.status_code == 200, providers_page.text
        assert "Cloudflare" in providers_page.text

        peers = await _asgi_request(
            app,
            "GET",
            "/cluster/peers?node_id=node-b",
            headers={"authorization": f"Bearer {lease_token}"},
        )
        assert peers.status_code == 200, peers.text
        peers_with_query_token = await _asgi_request(
            app,
            "GET",
            f"/cluster/peers?node_id=node-b&lease_token={lease_token}",
        )
        assert peers_with_query_token.status_code == 401

        active_content = await _asgi_request(
            app,
            "GET",
            "/cluster/content/active?node_id=node-b",
            headers={"authorization": f"Bearer {lease_token}"},
        )
        assert active_content.status_code == 200, active_content.text

        role_placement = await _asgi_request(
            app,
            "GET",
            "/roles/placement?node_id=node-b",
            headers={"authorization": f"Bearer {lease_token}"},
        )
        assert role_placement.status_code == 200, role_placement.text

        gateway_config = await _asgi_request(
            app,
            "GET",
            "/gateway/nginx/config",
            headers=auth_headers,
        )
        assert gateway_config.status_code == 200, gateway_config.text
        assert "server" in gateway_config.text

        gateway_source_map = await _asgi_request(
            app,
            "GET",
            "/gateway/nginx/source-map",
            headers=auth_headers,
        )
        assert gateway_source_map.status_code == 200, gateway_source_map.text
        assert json.loads(gateway_source_map.text)

        preflight = await _asgi_request(app, "GET", "/system/preflight", headers=auth_headers)
        assert preflight.status_code == 200, preflight.text
        assert "checks" in preflight.json()

        inventory = await _asgi_request(app, "GET", "/system/runtime-inventory", headers=auth_headers)
        assert inventory.status_code == 200, inventory.text
        assert inventory.json()["counts"]["managed_runtime"] >= 1

        runbook = await _asgi_request(app, "GET", "/system/runbook", headers=auth_headers)
        assert runbook.status_code == 200, runbook.text
        assert "UptimeMesh Recovery Runbook" in runbook.text

        support_bundle = await _asgi_request(
            app,
            "POST",
            "/support-bundles",
            headers=auth_headers,
            json_body={"id": "smoke-bundle", "requested_by": "smoke"},
        )
        assert support_bundle.status_code == 201, support_bundle.text
        assert support_bundle.json()["id"] == "smoke-bundle"

        nodes_page = await _asgi_request(app, "GET", "/ui/nodes", headers=auth_headers)
        assert nodes_page.status_code == 200, nodes_page.text
        assert "Role Placement" in nodes_page.text
        assert "backend_server" in nodes_page.text
        csrf_match = re.search(r'name="csrf_token" value="([^"]+)"', nodes_page.text)
        assert csrf_match
        csrf_token = csrf_match.group(1)

        join_command_without_csrf = await _asgi_request(
            app,
            "POST",
            "/ui/nodes/join-command",
            headers=auth_headers,
            form_body={"peer": "127.0.0.1", "role": "auto", "ttl_seconds": "600", "join_port": "8010"},
        )
        assert join_command_without_csrf.status_code == 403

        join_command = await _asgi_request(
            app,
            "POST",
            "/ui/nodes/join-command",
            headers=auth_headers,
            form_body={
                "csrf_token": csrf_token,
                "peer": "127.0.0.1",
                "role": "auto",
                "ttl_seconds": "600",
                "join_port": "8010",
            },
        )
        assert join_command.status_code == 200, join_command.text
        assert "--token" not in join_command.json()["install_command"]
        assert join_command.json()["join_token"]

        roles_page = await _asgi_request(app, "GET", "/ui/roles", headers=auth_headers)
        assert roles_page.status_code == 200, roles_page.text
        assert "reverse_proxy" in roles_page.text

        simulator_seed = await _asgi_request(
            app,
            "POST",
            "/system/simulator/seed",
            headers=auth_headers,
        )
        assert simulator_seed.status_code == 201, simulator_seed.text
        assert simulator_seed.json()["node_count"] == 3

    asyncio.run(scenario())
