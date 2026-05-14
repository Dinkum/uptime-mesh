from __future__ import annotations

import json
import hashlib
import re
from pathlib import Path

from app.config import Settings
from app.identity import heartbeat_signing_message
from app.models.snapshot_run import SnapshotRun
from app.models.support_bundle import SupportBundle
from app.services.snapshots import _snapshot_restore_dir
from app.services.snapshots import snapshot_artifact_path
from app.services.support_bundles import support_bundle_artifact_path

ROOT = Path(__file__).resolve().parents[1]
GO_AGENT = ROOT / "agent/cmd/uptimemesh-agent/main.go"
VERSION_JSON = ROOT / "version.json"
ENV_EXAMPLE = ROOT / ".env.example"
INSTALL_SH = ROOT / "install.sh"
BOOTSTRAP_SH = ROOT / "ops/bootstrap.sh"
UPDATE_SH = ROOT / "ops/update.sh"


def test_heartbeat_signing_message_wire_contract() -> None:
    non_ascii = chr(233)
    message = heartbeat_signing_message(
        node_id="node-a",
        lease_token="lease-token",
        signed_at=1_700_000_000,
        ttl_seconds=45,
        status_patch={"z": f"<tag>&{non_ascii}", "a": {"nested": True}},
    )

    assert (
        message
        == (
            'node-a\nlease-token\n1700000000\n45\n'
            f'{{"a":{{"nested":true}},"z":"<tag>&{non_ascii}"}}'
        ).encode("utf-8")
    )


def test_artifact_paths_must_stay_under_managed_directories(tmp_path: Path) -> None:
    snapshot = SnapshotRun(id="safe", location=str((ROOT / "data/etcd-snapshots/safe.db").resolve()))
    bundle = SupportBundle(
        id="safe",
        path=str((ROOT / "data/support-bundles/safe.tar.gz").resolve()),
    )

    assert snapshot_artifact_path(snapshot).name == "safe.db"
    assert support_bundle_artifact_path(bundle).name == "safe.tar.gz"

    snapshot.location = str(tmp_path / "escaped.db")
    bundle.path = str(tmp_path / "escaped.tar.gz")

    try:
        snapshot_artifact_path(snapshot)
    except ValueError as exc:
        assert "escapes" in str(exc)
    else:
        raise AssertionError("snapshot path escaped its managed directory")

    try:
        support_bundle_artifact_path(bundle)
    except ValueError as exc:
        assert "escapes" in str(exc)
    else:
        raise AssertionError("support bundle path escaped its managed directory")


def test_snapshot_restore_rejects_unsafe_snapshot_id_before_output_paths() -> None:
    try:
        _snapshot_restore_dir("../escaped", "20260514120000")
    except ValueError as exc:
        assert "snapshot id must be a safe artifact slug" in str(exc)
    else:
        raise AssertionError("unsafe snapshot id was accepted for restore")


def test_agent_version_matches_manifest() -> None:
    go_source = GO_AGENT.read_text()
    match = re.search(r'agentVersion\s+=\s+"([^"]+)"', go_source)
    assert match is not None

    manifest = json.loads(VERSION_JSON.read_text())
    assert match.group(1) == manifest["channels"]["stable"]["agent"]["version"]


def test_agent_runtime_env_keys_are_discoverable() -> None:
    env_text = ENV_EXAMPLE.read_text()
    go_source = GO_AGENT.read_text()
    setting_fields = set(Settings.model_fields)
    required_keys = {
        "RUNTIME_API_TIMEOUT_SECONDS": "runtime_api_timeout_seconds",
        "RUNTIME_COMMAND_TIMEOUT_SECONDS": "runtime_command_timeout_seconds",
        "RUNTIME_PING_TIMEOUT_SECONDS": "runtime_ping_timeout_seconds",
        "RUNTIME_SWIM_INDIRECT_PROBE_COUNT": "runtime_swim_indirect_probe_count",
    }

    for env_key, setting_name in required_keys.items():
        assert f"{env_key}=" in env_text
        assert setting_name in setting_fields

    assert 'parseInt("RUNTIME_API_TIMEOUT_SECONDS", 5)' in go_source
    assert 'parseInt("RUNTIME_COMMAND_TIMEOUT_SECONDS", 30)' in go_source
    assert 'parseInt("RUNTIME_PING_TIMEOUT_SECONDS", 1)' in go_source
    assert "if cfg.PingTimeoutSeconds > 30" in go_source


def test_manifest_script_checksums_match_scripts() -> None:
    manifest = json.loads(VERSION_JSON.read_text())
    scripts = {
        "bootstrap": BOOTSTRAP_SH,
        "install": INSTALL_SH,
        "update": UPDATE_SH,
    }

    for key, path in scripts.items():
        expected = manifest["channels"]["stable"][key]["sha256"]
        actual = hashlib.sha256(path.read_bytes()).hexdigest()
        assert actual == expected


def test_scheduler_dry_run_does_not_mutate_loaded_replica_objects() -> None:
    source = (ROOT / "app/services/scheduler.py").read_text()
    assert "if not dry_run:\n            replica.node_id = target_node.id" in source
    assert "if not dry_run:\n            replica.status = status" in source


def test_agent_reports_explicit_role_runtime_capabilities() -> None:
    go_source = GO_AGENT.read_text()
    assert 'actuatedRuntimeRoles = []string{"backend_server", "reverse_proxy"}' in go_source
    assert '"role_runtime_capabilities": append([]string{}, actuatedRuntimeRoles...)' in go_source
