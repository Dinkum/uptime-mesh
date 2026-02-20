from __future__ import annotations

import argparse
import os
import subprocess
import sys
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Tuple

from app.logger import configure_logging, get_logger


@dataclass(frozen=True)
class CommandResult:
    code: int
    stdout: str
    stderr: str


def _run_command(args: list[str]) -> CommandResult:
    proc = subprocess.run(args, capture_output=True, text=True, check=False)
    return CommandResult(
        code=proc.returncode,
        stdout=(proc.stdout or "").strip(),
        stderr=(proc.stderr or "").strip(),
    )


def _trim(value: str, max_len: int = 240) -> str:
    text = value.strip()
    if len(text) <= max_len:
        return text
    return text[: max_len - 3] + "..."


def _service_state(service_name: str) -> Tuple[bool, bool]:
    active = _run_command(["systemctl", "is-active", service_name]).code == 0
    enabled_cmd = _run_command(["systemctl", "is-enabled", service_name])
    enabled = enabled_cmd.code == 0 and enabled_cmd.stdout in {"enabled", "static", "indirect"}
    return active, enabled


def _restart_service(service_name: str) -> CommandResult:
    return _run_command(["systemctl", "restart", service_name])


def _health_check(url: str, timeout_seconds: int) -> Tuple[bool, int, str]:
    request = urllib.request.Request(url=url, method="GET")
    try:
        with urllib.request.urlopen(request, timeout=timeout_seconds) as resp:
            status = int(getattr(resp, "status", 0) or 0)
            return (200 <= status < 300, status, "")
    except urllib.error.HTTPError as exc:
        return (False, int(getattr(exc, "code", 0) or 0), f"HTTPError: {exc}")
    except Exception as exc:  # noqa: BLE001
        return (False, 0, f"{type(exc).__name__}: {exc}")


def _log_step(logger, severity: str, step: str, message: str, **fields: object) -> None:
    payload = {"step": step, **fields}
    if severity == "warning":
        logger.warning("operation.step", message, **payload)
        return
    if severity == "error":
        logger.error("operation.step", message, **payload)
        return
    logger.info("operation.step", message, **payload)


def main() -> int:
    parser = argparse.ArgumentParser(description="UptimeMesh local self-heal watchdog")
    parser.add_argument("--api-url", default="http://127.0.0.1:8010/health")
    parser.add_argument("--api-service", default="uptime-mesh.service")
    parser.add_argument("--agent-service", default="uptime-mesh-agent.service")
    parser.add_argument("--health-timeout-seconds", type=int, default=4)
    parser.add_argument("--restart-grace-seconds", type=int, default=2)
    args = parser.parse_args()

    configure_logging(
        log_level=os.getenv("LOG_LEVEL", "INFO"),
        log_file=os.getenv("LOG_FILE", "./data/logs/app.log"),
    )
    logger = get_logger("watchdog")

    logger.info(
        "watchdog.run",
        "Started local self-heal check",
        api_url=args.api_url,
        api_service=args.api_service,
        agent_service=args.agent_service,
    )

    failures: list[str] = []
    repairs = 0

    api_active, api_enabled = _service_state(args.api_service)
    _log_step(
        logger,
        "info",
        "api.service",
        "Checked API service state",
        service=args.api_service,
        active=api_active,
        enabled=api_enabled,
    )
    if api_enabled and not api_active:
        restart = _restart_service(args.api_service)
        repairs += 1
        _log_step(
            logger,
            "warning" if restart.code == 0 else "error",
            "api.restart",
            "Restarted inactive API service" if restart.code == 0 else "Failed to restart inactive API service",
            service=args.api_service,
            exit_code=restart.code,
            stderr=_trim(restart.stderr),
        )
        time.sleep(max(args.restart_grace_seconds, 1))
        api_active, _ = _service_state(args.api_service)
        if not api_active:
            failures.append("api_service_still_inactive")

    api_ok, api_status, api_error = _health_check(args.api_url, args.health_timeout_seconds)
    _log_step(
        logger,
        "info" if api_ok else "warning",
        "api.health",
        "Probed API health endpoint" if api_ok else "API health endpoint failed",
        url=args.api_url,
        healthy=api_ok,
        status_code=api_status,
        error=_trim(api_error),
    )
    if not api_ok and api_enabled:
        restart = _restart_service(args.api_service)
        repairs += 1
        _log_step(
            logger,
            "warning" if restart.code == 0 else "error",
            "api.health_restart",
            "Restarted API after failed health probe" if restart.code == 0 else "Failed API restart after failed health probe",
            service=args.api_service,
            exit_code=restart.code,
            stderr=_trim(restart.stderr),
        )
        time.sleep(max(args.restart_grace_seconds, 1))
        api_ok, api_status, api_error = _health_check(args.api_url, args.health_timeout_seconds)
        _log_step(
            logger,
            "info" if api_ok else "error",
            "api.health_recheck",
            "API recovered after restart" if api_ok else "API still unhealthy after restart",
            url=args.api_url,
            healthy=api_ok,
            status_code=api_status,
            error=_trim(api_error),
        )
        if not api_ok:
            failures.append("api_health_unhealthy_after_restart")

    agent_active, agent_enabled = _service_state(args.agent_service)
    _log_step(
        logger,
        "info",
        "agent.service",
        "Checked agent service state",
        service=args.agent_service,
        active=agent_active,
        enabled=agent_enabled,
    )
    if agent_enabled and not agent_active:
        restart = _restart_service(args.agent_service)
        repairs += 1
        _log_step(
            logger,
            "warning" if restart.code == 0 else "error",
            "agent.restart",
            "Restarted inactive agent service" if restart.code == 0 else "Failed to restart inactive agent service",
            service=args.agent_service,
            exit_code=restart.code,
            stderr=_trim(restart.stderr),
        )
        time.sleep(max(args.restart_grace_seconds, 1))
        agent_active, _ = _service_state(args.agent_service)
        if not agent_active:
            failures.append("agent_service_still_inactive")

    if failures:
        logger.error(
            "watchdog.result",
            "Self-heal check failed",
            failures=len(failures),
            details=",".join(failures),
            repairs_attempted=repairs,
        )
        return 1

    if repairs > 0:
        logger.warning(
            "watchdog.result",
            "Self-heal check completed with repairs",
            repairs_applied=repairs,
        )
    else:
        logger.info("watchdog.result", "Self-heal check completed", repairs_applied=0)
    return 0


if __name__ == "__main__":
    sys.exit(main())
