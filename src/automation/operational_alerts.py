"""Privacy-minimized operational alert delivery.

This module is deliberately separate from ``email_monitor.AlertDispatcher``.
Phishing alerts contain mailbox evidence for a private analyst workflow, while
operational alerts use a closed schema suitable for a general operations
webhook. See ADR 0003.
"""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
import logging
import os
import re
import threading
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable
from urllib.parse import urlparse

import aiohttp

logger = logging.getLogger(__name__)

DEFAULT_LOG_PATH = "data/operational_alerts.jsonl"
DEFAULT_COOLDOWN_SECONDS = 15 * 60
MAX_DEDUPE_ENTRIES = 4096

_EVENT_SCHEMAS: dict[str, dict[str, type]] = {
    "analyzer_circuit_open": {
        "analyzer": str,
        "failure_count": int,
        "recovery_timeout_seconds": int,
    },
    "auth_failure_threshold": {
        "auth_namespace": str,
        "attempt_count": int,
        "window_seconds": int,
    },
    "tenant_campaign_repeated": {
        "related_count": int,
        "signal_types": list,
        "payment_risk": bool,
    },
    "payment_risk_escalation": {
        "decision": str,
        "related_count": int,
    },
}

_EVENT_METADATA = {
    "analyzer_circuit_open": {
        "severity": "high",
        "summary": "An external analyzer circuit opened after repeated failures.",
    },
    "auth_failure_threshold": {
        "severity": "high",
        "summary": "A login failure budget reached its throttle threshold.",
    },
    "tenant_campaign_repeated": {
        "severity": "high",
        "summary": "A workspace recorded another scan linked to a repeated campaign.",
    },
    "payment_risk_escalation": {
        "severity": "critical",
        "summary": "PayShield produced a do-not-pay-until-verified decision.",
    },
}

_ALLOWED_SIGNAL_TYPES = {
    "attachment_hash",
    "payment_decision",
    "sender",
    "sender_domain",
    "url",
    "url_domain",
}
_ALLOWED_AUTH_NAMESPACES = {"analyst", "saas-user"}
_ALLOWED_PAYMENT_DECISIONS = {"DO_NOT_PAY", "DO_NOT_PAY_UNTIL_VERIFIED"}
_SAFE_LABEL = re.compile(r"^[A-Za-z0-9_.:-]{1,80}$")
_LOG_WRITE_LOCK = threading.Lock()


def _positive_int_from_env(name: str, default: int) -> int:
    raw = os.getenv(name, str(default)).strip()
    try:
        value = int(raw)
    except ValueError:
        logger.warning("Invalid %s; using %s", name, default)
        return default
    if value < 0:
        logger.warning("%s must be non-negative; using %s", name, default)
        return default
    return value


def _validate_webhook_url(value: str) -> str:
    url = value.strip()
    if not url:
        return ""
    parsed = urlparse(url)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise ValueError("OPERATIONAL_ALERT_WEBHOOK_URL must be an absolute http(s) URL")
    if parsed.username or parsed.password:
        raise ValueError("Webhook URL userinfo is not supported")
    return url


def _validate_details(event_type: str, details: dict[str, Any]) -> dict[str, Any]:
    schema = _EVENT_SCHEMAS.get(event_type)
    if schema is None:
        raise ValueError(f"Unsupported operational alert event: {event_type}")
    if set(details) != set(schema):
        unknown = sorted(set(details) - set(schema))
        missing = sorted(set(schema) - set(details))
        raise ValueError(
            "Operational alert details do not match the privacy schema "
            f"(unknown={unknown}, missing={missing})"
        )

    normalized: dict[str, Any] = {}
    for key, expected_type in schema.items():
        value = details[key]
        if expected_type is int:
            if isinstance(value, bool) or not isinstance(value, int) or value < 0:
                raise ValueError(f"Operational alert field {key} must be a non-negative integer")
        elif expected_type is bool:
            if not isinstance(value, bool):
                raise ValueError(f"Operational alert field {key} must be a boolean")
        elif expected_type is str:
            if not isinstance(value, str) or not _SAFE_LABEL.fullmatch(value):
                raise ValueError(f"Operational alert field {key} contains an unsafe label")
        elif expected_type is list:
            if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
                raise ValueError(f"Operational alert field {key} must be a string list")
            if len(value) > len(_ALLOWED_SIGNAL_TYPES):
                raise ValueError(f"Operational alert field {key} contains too many values")
        normalized[key] = value

    if event_type == "auth_failure_threshold":
        if normalized["auth_namespace"] not in _ALLOWED_AUTH_NAMESPACES:
            raise ValueError("Unsupported authentication namespace")
    elif event_type == "payment_risk_escalation":
        if normalized["decision"] not in _ALLOWED_PAYMENT_DECISIONS:
            raise ValueError("Unsupported payment escalation decision")
    elif event_type == "tenant_campaign_repeated":
        signal_types = sorted(set(normalized["signal_types"]))
        if not set(signal_types).issubset(_ALLOWED_SIGNAL_TYPES):
            raise ValueError("Unsupported campaign signal type")
        normalized["signal_types"] = signal_types
    return normalized


class OperationalAlertDispatcher:
    """Persist and optionally deliver privacy-minimized operational alerts."""

    def __init__(
        self,
        *,
        log_path: str | Path = DEFAULT_LOG_PATH,
        webhook_url: str = "",
        hash_key: str = "",
        cooldown_seconds: int = DEFAULT_COOLDOWN_SECONDS,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self.log_path = Path(log_path)
        self.webhook_url = _validate_webhook_url(webhook_url)
        self._hash_key = hash_key.encode("utf-8") if hash_key else b""
        self.cooldown_seconds = max(0, int(cooldown_seconds))
        self._clock = clock
        self._recent_events: dict[str, float] = {}

    @classmethod
    def from_env(cls) -> "OperationalAlertDispatcher":
        return cls(
            log_path=os.getenv("OPERATIONAL_ALERT_LOG_PATH", DEFAULT_LOG_PATH),
            webhook_url=(
                os.getenv("OPERATIONAL_ALERT_WEBHOOK_URL", "").strip()
                or os.getenv("ALERT_WEBHOOK_URL", "").strip()
            ),
            hash_key=os.getenv("OPERATIONAL_ALERT_HASH_KEY", ""),
            cooldown_seconds=_positive_int_from_env(
                "OPERATIONAL_ALERT_COOLDOWN_SECONDS",
                DEFAULT_COOLDOWN_SECONDS,
            ),
        )

    def _tenant_ref(self, tenant_id: str | None) -> str | None:
        if not tenant_id or not self._hash_key:
            return None
        digest = hmac.new(
            self._hash_key,
            tenant_id.encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()
        return f"tenant_{digest[:16]}"

    def _is_suppressed(self, dedupe_key: str) -> bool:
        if self.cooldown_seconds <= 0:
            return False
        now = self._clock()
        cutoff = now - self.cooldown_seconds
        self._recent_events = {
            key: recorded_at
            for key, recorded_at in self._recent_events.items()
            if recorded_at > cutoff
        }
        previous = self._recent_events.get(dedupe_key)
        if previous is not None and now - previous < self.cooldown_seconds:
            return True
        if len(self._recent_events) >= MAX_DEDUPE_ENTRIES:
            oldest = min(
                self._recent_events,
                key=lambda key: self._recent_events[key],
            )
            self._recent_events.pop(oldest, None)
        self._recent_events[dedupe_key] = now
        return False

    async def dispatch(
        self,
        event_type: str,
        *,
        details: dict[str, Any],
        tenant_id: str | None = None,
        dedupe_key: str | None = None,
    ) -> dict[str, Any]:
        """Validate, persist, and optionally POST one operational alert."""
        safe_details = _validate_details(event_type, details)
        internal_dedupe_key = dedupe_key or json.dumps(
            [event_type, tenant_id or "", safe_details],
            sort_keys=True,
            separators=(",", ":"),
        )
        if self._is_suppressed(internal_dedupe_key):
            return {
                "status": "suppressed",
                "event_type": event_type,
                "log_written": False,
                "webhook_configured": bool(self.webhook_url),
                "webhook_delivered": False,
            }

        metadata = _EVENT_METADATA[event_type]
        payload: dict[str, Any] = {
            "schema_version": 1,
            "alert_id": f"op_{uuid.uuid4().hex}",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "event_type": event_type,
            "severity": metadata["severity"],
            "summary": metadata["summary"],
            "details": safe_details,
        }
        tenant_ref = self._tenant_ref(tenant_id)
        if tenant_ref:
            payload["tenant_ref"] = tenant_ref

        log_written = await asyncio.to_thread(self._write_jsonl, payload)
        webhook_delivered = False
        if self.webhook_url:
            webhook_delivered = await self._deliver_webhook(payload)

        if log_written and (not self.webhook_url or webhook_delivered):
            status = "delivered" if self.webhook_url else "logged"
        elif log_written or webhook_delivered:
            status = "partial"
        else:
            status = "failed"
        return {
            "status": status,
            "event_type": event_type,
            "log_written": log_written,
            "webhook_configured": bool(self.webhook_url),
            "webhook_delivered": webhook_delivered,
            "payload": payload,
        }

    def _write_jsonl(self, payload: dict[str, Any]) -> bool:
        try:
            line = json.dumps(payload, sort_keys=True, separators=(",", ":")) + "\n"
            with _LOG_WRITE_LOCK:
                self.log_path.parent.mkdir(parents=True, exist_ok=True)
                with self.log_path.open("a", encoding="utf-8", newline="\n") as handle:
                    handle.write(line)
            return True
        except OSError as exc:
            logger.error(
                "Operational alert log write failed for event=%s path=%s error=%s",
                payload["event_type"],
                self.log_path,
                type(exc).__name__,
            )
            return False

    async def _deliver_webhook(self, payload: dict[str, Any]) -> bool:
        try:
            timeout = aiohttp.ClientTimeout(total=10)
            async with aiohttp.ClientSession(timeout=timeout) as session:
                async with session.post(self.webhook_url, json=payload) as response:
                    if response.status >= 300:
                        logger.error(
                            "Operational alert webhook rejected event=%s status=%s",
                            payload["event_type"],
                            response.status,
                        )
                        return False
                    return True
        except (aiohttp.ClientError, asyncio.TimeoutError, OSError) as exc:
            logger.error(
                "Operational alert webhook failed for event=%s error=%s",
                payload["event_type"],
                type(exc).__name__,
            )
            return False
