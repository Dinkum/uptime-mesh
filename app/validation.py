from __future__ import annotations

import ipaddress
import re
from pathlib import Path
from urllib.parse import urlsplit

_ARTIFACT_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$")
_MESH_ID_RE = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9_.:-]{0,127}$")
_DNS_LABEL_RE = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")
_NGINX_UPSTREAM_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,63}$")


def artifact_id(value: str, *, field_name: str = "artifact id") -> str:
    clean = str(value or "").strip()
    if not _ARTIFACT_ID_RE.fullmatch(clean):
        raise ValueError(f"{field_name} must be a safe artifact slug")
    return clean


def mesh_id(value: str, *, field_name: str = "id") -> str:
    clean = str(value or "").strip()
    if not _MESH_ID_RE.fullmatch(clean):
        raise ValueError(f"{field_name} must be a safe mesh id")
    return clean


def port(value: object, *, field_name: str = "port") -> int:
    try:
        parsed = int(value)  # type: ignore[arg-type]
    except (TypeError, ValueError) as exc:
        raise ValueError(f"{field_name} must be numeric") from exc
    if parsed < 1 or parsed > 65535:
        raise ValueError(f"{field_name} must be between 1 and 65535")
    return parsed


def dns_name(value: str, *, field_name: str = "domain", allow_wildcard: bool = False) -> str:
    clean = str(value or "").strip().lower().rstrip(".")
    if clean == "_":
        return clean
    if allow_wildcard and clean.startswith("*."):
        clean = clean[2:]
    if not clean or len(clean) > 253:
        raise ValueError(f"{field_name} must be a valid DNS name")
    labels = clean.split(".")
    if any(not _DNS_LABEL_RE.fullmatch(label) for label in labels):
        raise ValueError(f"{field_name} must be a valid DNS name")
    return f"*.{clean}" if allow_wildcard and str(value).strip().startswith("*.") else clean


def ip_address(value: str, *, field_name: str = "address") -> str:
    clean = str(value or "").strip()
    try:
        return str(ipaddress.ip_address(clean))
    except ValueError as exc:
        raise ValueError(f"{field_name} must be a valid IP address") from exc


def host_or_ip(value: str, *, field_name: str = "host") -> str:
    clean = str(value or "").strip().lower().rstrip(".")
    try:
        return str(ipaddress.ip_address(clean))
    except ValueError:
        return dns_name(clean, field_name=field_name)


def nginx_path(value: str, *, field_name: str = "path") -> str:
    clean = str(value or "").strip() or "/"
    if not clean.startswith("/"):
        raise ValueError(f"{field_name} must start with /")
    if any(ch in clean for ch in "{};\\\r\n\t"):
        raise ValueError(f"{field_name} contains unsafe NGINX characters")
    if "://" in clean:
        raise ValueError(f"{field_name} must be a path, not a URL")
    return clean


def nginx_upstream_name(value: str, *, field_name: str = "upstream") -> str:
    clean = str(value or "").strip()
    if not _NGINX_UPSTREAM_RE.fullmatch(clean):
        raise ValueError(f"{field_name} must be a safe NGINX upstream name")
    return clean


def nginx_listen(value: str, *, field_name: str = "listen") -> str:
    clean = str(value or "").strip() or "0.0.0.0:8080"
    if any(ch in clean for ch in "{};\\\r\n\t"):
        raise ValueError(f"{field_name} contains unsafe NGINX characters")
    if clean.isdigit():
        return str(port(clean, field_name=field_name))
    if clean.startswith("["):
        host, sep, raw_port = clean.rpartition("]:")
        if sep:
            ip_address(host.strip("[]"), field_name=field_name)
            return f"[{host.strip('[]')}]:{port(raw_port, field_name=field_name)}"
    host, sep, raw_port = clean.rpartition(":")
    if sep:
        if host:
            host_or_ip(host, field_name=field_name)
        return f"{host}:{port(raw_port, field_name=field_name)}"
    host_or_ip(clean, field_name=field_name)
    return clean


def upstream_endpoint(address: str, endpoint_port: object) -> tuple[str, int]:
    clean_address = host_or_ip(address, field_name="endpoint address")
    return clean_address, port(endpoint_port, field_name="endpoint port")


def corefile_listen(value: str) -> str:
    clean = str(value or "").strip() or ".:53"
    if clean.startswith(".:"):
        return f".:{port(clean[2:], field_name='CoreDNS listen port')}"
    return nginx_listen(clean, field_name="CoreDNS listen")


def corefile_forwarders(raw: str) -> list[str]:
    values = [item.strip() for item in str(raw or "").split() if item.strip()]
    if not values:
        return ["/etc/resolv.conf"]
    forwarders: list[str] = []
    for value in values:
        if value == "/etc/resolv.conf":
            forwarders.append(value)
            continue
        if value.startswith(("tls://", "https://", "grpc://")):
            parsed = urlsplit(value)
            if not parsed.hostname:
                raise ValueError("CoreDNS forwarder URL must include a host")
            host_or_ip(parsed.hostname, field_name="CoreDNS forwarder host")
            if parsed.port is not None:
                port(parsed.port, field_name="CoreDNS forwarder port")
            forwarders.append(value)
            continue
        host, sep, raw_port = value.rpartition(":")
        if sep and host:
            host_or_ip(host, field_name="CoreDNS forwarder host")
            forwarders.append(f"{host}:{port(raw_port, field_name='CoreDNS forwarder port')}")
        else:
            forwarders.append(host_or_ip(value, field_name="CoreDNS forwarder host"))
    return forwarders


def path_under(base: Path, candidate: Path, *, field_name: str = "path") -> Path:
    resolved_base = base.resolve()
    resolved_candidate = candidate.resolve()
    if not resolved_candidate.is_relative_to(resolved_base):
        raise ValueError(f"{field_name} escapes managed directory")
    return resolved_candidate
