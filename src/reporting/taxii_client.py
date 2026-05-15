"""Optional TAXII 2.1 transport for STIX export bundles.

The project already writes STIX 2.1 bundles to files. This module adds the
transport layer without making TAXII a hard runtime dependency or exposing
credentials in status payloads.
"""
from __future__ import annotations

import base64
import json
import os
import ssl
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import quote, urlsplit, urlunsplit


TAXII_MEDIA_TYPE = "application/taxii+json;version=2.1"
DEFAULT_TAXII_STATUS_PATH = Path("data/taxii_push_status.json")


class TaxiiPushError(RuntimeError):
    """Raised when a STIX bundle cannot be delivered to TAXII."""


@dataclass(frozen=True)
class TaxiiPushConfig:
    enabled: bool = False
    base_url: str = ""
    collection_id: str = ""
    objects_url: str = ""
    username: str = ""
    password: str = ""
    bearer_token: str = ""
    timeout_seconds: float = 15.0
    verify_tls: bool = True
    status_path: Path = DEFAULT_TAXII_STATUS_PATH

    @property
    def configured(self) -> bool:
        return bool(self.objects_url.strip() or (self.base_url.strip() and self.collection_id.strip()))

    @classmethod
    def from_env(cls) -> "TaxiiPushConfig":
        return cls(
            enabled=_env_bool("TAXII_PUSH_ENABLED", False),
            base_url=os.getenv("TAXII_BASE_URL", "").strip(),
            collection_id=os.getenv("TAXII_COLLECTION_ID", "").strip(),
            objects_url=os.getenv("TAXII_OBJECTS_URL", "").strip(),
            username=os.getenv("TAXII_USERNAME", "").strip(),
            password=os.getenv("TAXII_PASSWORD", "").strip(),
            bearer_token=os.getenv("TAXII_BEARER_TOKEN", "").strip(),
            timeout_seconds=_env_float("TAXII_TIMEOUT_SECONDS", 15.0),
            verify_tls=_env_bool("TAXII_VERIFY_TLS", True),
            status_path=Path(os.getenv("TAXII_STATUS_PATH", str(DEFAULT_TAXII_STATUS_PATH))).expanduser(),
        )


@dataclass(frozen=True)
class TaxiiPushResult:
    status: str
    success: bool
    enabled: bool
    configured: bool
    object_count: int = 0
    http_status: int | None = None
    target: str = ""
    message: str = ""
    error_type: str = ""
    started_at: str = ""
    completed_at: str = ""
    duration_ms: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "status": self.status,
            "success": self.success,
            "enabled": self.enabled,
            "configured": self.configured,
            "object_count": self.object_count,
            "http_status": self.http_status,
            "target": self.target,
            "message": self.message,
            "error_type": self.error_type,
            "started_at": self.started_at,
            "completed_at": self.completed_at,
            "duration_ms": self.duration_ms,
        }


def prepare_taxii_envelope(stix_bundle_json: str | bytes | dict[str, Any]) -> dict[str, list[dict[str, Any]]]:
    """Return the TAXII Add Objects envelope for a STIX Bundle."""
    if isinstance(stix_bundle_json, bytes):
        payload = json.loads(stix_bundle_json.decode("utf-8-sig"))
    elif isinstance(stix_bundle_json, str):
        payload = json.loads(stix_bundle_json.lstrip("\ufeff"))
    elif isinstance(stix_bundle_json, dict):
        payload = stix_bundle_json
    else:
        raise TaxiiPushError("STIX bundle must be JSON text, bytes, or a dictionary")

    if payload.get("type") != "bundle":
        raise TaxiiPushError("STIX payload is not a bundle")
    objects = payload.get("objects")
    if not isinstance(objects, list) or not objects:
        raise TaxiiPushError("STIX bundle has no objects to push")
    if not all(isinstance(item, dict) and item.get("type") for item in objects):
        raise TaxiiPushError("STIX bundle contains malformed objects")
    return {"objects": objects}


def build_taxii_objects_url(config: TaxiiPushConfig) -> str:
    if config.objects_url.strip():
        return config.objects_url.strip()
    if not config.base_url.strip() or not config.collection_id.strip():
        raise TaxiiPushError("TAXII_BASE_URL and TAXII_COLLECTION_ID are required")
    base = config.base_url.strip().rstrip("/")
    collection_id = quote(config.collection_id.strip(), safe="")
    return f"{base}/collections/{collection_id}/objects/"


def push_stix_bundle(
    stix_bundle_json: str | bytes | dict[str, Any],
    *,
    config: TaxiiPushConfig | None = None,
    opener=urllib.request.urlopen,
) -> TaxiiPushResult:
    """Push a STIX Bundle to a TAXII 2.1 collection when enabled."""
    config = config or TaxiiPushConfig.from_env()
    started_at = _now_iso()
    started = time.perf_counter()

    def finish(
        status: str,
        *,
        success: bool,
        object_count: int = 0,
        http_status: int | None = None,
        target: str = "",
        message: str = "",
        error_type: str = "",
    ) -> TaxiiPushResult:
        completed_at = _now_iso()
        return TaxiiPushResult(
            status=status,
            success=success,
            enabled=config.enabled,
            configured=config.configured,
            object_count=object_count,
            http_status=http_status,
            target=_safe_url_for_status(target),
            message=message,
            error_type=error_type,
            started_at=started_at,
            completed_at=completed_at,
            duration_ms=max(0, round((time.perf_counter() - started) * 1000)),
        )

    if not config.enabled:
        return finish("skipped", success=True, message="TAXII push is disabled")
    if not config.configured:
        return finish(
            "not_configured",
            success=False,
            message="TAXII push is enabled but no collection endpoint is configured",
            error_type="configuration",
        )

    try:
        envelope = prepare_taxii_envelope(stix_bundle_json)
        objects_url = build_taxii_objects_url(config)
        request = urllib.request.Request(
            objects_url,
            data=json.dumps(envelope, separators=(",", ":"), ensure_ascii=True).encode("utf-8"),
            method="POST",
            headers={
                "Accept": TAXII_MEDIA_TYPE,
                "Content-Type": TAXII_MEDIA_TYPE,
                "User-Agent": "PhishAnalyze-TAXII/1.0",
            },
        )
        _apply_auth_headers(request, config)
        context = None if config.verify_tls else ssl._create_unverified_context()
        response = opener(request, timeout=config.timeout_seconds, context=context)
        with response:
            http_status = int(getattr(response, "status", getattr(response, "code", 0)) or 0)
            if http_status and http_status >= 400:
                return finish(
                    "failed",
                    success=False,
                    object_count=len(envelope["objects"]),
                    http_status=http_status,
                    target=objects_url,
                    message=f"TAXII server returned HTTP {http_status}",
                    error_type="http_error",
                )
        return finish(
            "success",
            success=True,
            object_count=len(envelope["objects"]),
            http_status=http_status or 202,
            target=objects_url,
            message="STIX objects accepted by TAXII collection",
        )
    except urllib.error.HTTPError as exc:
        return finish(
            "failed",
            success=False,
            http_status=int(exc.code or 0),
            target=getattr(exc, "url", ""),
            message=f"TAXII server returned HTTP {exc.code}",
            error_type="http_error",
        )
    except TimeoutError:
        return finish("timeout", success=False, message="TAXII push timed out", error_type="timeout")
    except Exception as exc:
        return finish(
            "failed",
            success=False,
            message=_safe_error_message(exc),
            error_type=exc.__class__.__name__,
        )


def write_taxii_status(result: TaxiiPushResult, path: str | Path) -> Path:
    status_path = Path(path)
    status_path.parent.mkdir(parents=True, exist_ok=True)
    status_path.write_text(json.dumps(result.to_dict(), indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return status_path


def _apply_auth_headers(request: urllib.request.Request, config: TaxiiPushConfig) -> None:
    if config.bearer_token:
        request.add_header("Authorization", f"Bearer {config.bearer_token}")
    elif config.username or config.password:
        raw = f"{config.username}:{config.password}".encode("utf-8")
        request.add_header("Authorization", "Basic " + base64.b64encode(raw).decode("ascii"))


def _safe_url_for_status(value: str) -> str:
    if not value:
        return ""
    parts = urlsplit(value)
    netloc = parts.netloc
    if "@" in netloc:
        netloc = netloc.rsplit("@", 1)[-1]
    return urlunsplit((parts.scheme, netloc, parts.path, "", ""))


def _safe_error_message(exc: Exception) -> str:
    message = str(exc) or exc.__class__.__name__
    for key in ("TAXII_PASSWORD", "TAXII_BEARER_TOKEN"):
        secret = os.getenv(key, "")
        if secret:
            message = message.replace(secret, "[redacted]")
    return message[:240]


def _env_bool(name: str, default: bool) -> bool:
    value = os.getenv(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def _env_float(name: str, default: float) -> float:
    try:
        return float(os.getenv(name, str(default)))
    except (TypeError, ValueError):
        return default


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()
