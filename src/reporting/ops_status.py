"""Privacy-preserving operational status summaries for admin views."""
from __future__ import annotations
import logging

import json
import os
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit, urlunsplit

from src.eval.payment_dataset import DEFAULT_DATASET_DIR, REPORTS_DIR
from src.reporting.taxii_client import DEFAULT_TAXII_STATUS_PATH, TaxiiPushConfig

logger = logging.getLogger(__name__)


DEFAULT_SIGMA_CONVERSION_STATUS_PATH = Path("data/sigma_conversion_status.json")
DEFAULT_PAYMENT_ASSURANCE_REPORT_PATH = DEFAULT_DATASET_DIR / REPORTS_DIR / "payment_assurance_report.json"


def cti_transport_overview() -> dict[str, Any]:
    """Return safe TAXII/Sigma transport state for the admin console."""
    taxii_config = TaxiiPushConfig.from_env()
    sigma_status_path = Path(
        os.getenv("SIGMA_CONVERSION_STATUS_PATH", str(DEFAULT_SIGMA_CONVERSION_STATUS_PATH))
    ).expanduser()
    taxii_status = _read_status(taxii_config.status_path or DEFAULT_TAXII_STATUS_PATH)
    sigma_status = _read_status(sigma_status_path)
    return {
        "taxii": {
            "enabled": taxii_config.enabled,
            "configured": taxii_config.configured,
            "status": taxii_status.get("status", "never_run"),
            "success": bool(taxii_status.get("success", False)),
            "object_count": _safe_int(taxii_status.get("object_count")),
            "http_status": taxii_status.get("http_status"),
            "target": _safe_url(str(taxii_status.get("target") or "")),
            "message": _safe_text(taxii_status.get("message")),
            "error_type": str(taxii_status.get("error_type") or "")[:80],
            "completed_at": str(taxii_status.get("completed_at") or ""),
            "duration_ms": _safe_int(taxii_status.get("duration_ms")),
        },
        "sigma_conversion": {
            "status": sigma_status.get("status", "never_run"),
            "success": bool(sigma_status.get("success", False)),
            "backend": str(sigma_status.get("backend") or ""),
            "rules_checked": _safe_int(sigma_status.get("rules_checked")),
            "rules_converted": _safe_int(sigma_status.get("rules_converted")),
            "query_count": _safe_int(sigma_status.get("query_count")),
            "failure_count": _safe_int(sigma_status.get("failure_count")),
            "completed_at": str(sigma_status.get("completed_at") or ""),
            "duration_ms": _safe_int(sigma_status.get("duration_ms")),
        },
    }


def payment_assurance_overview() -> dict[str, Any]:
    """Return aggregate payment-corpus assurance state without sample contents."""
    report_path = Path(
        os.getenv("PAYMENT_ASSURANCE_STATUS_PATH", str(DEFAULT_PAYMENT_ASSURANCE_REPORT_PATH))
    ).expanduser()
    report = _read_status(report_path)
    if not report:
        return {
            "status": "never_run",
            "ready": False,
            "row_count": 0,
            "real_redacted_total": 0,
            "pii_free_real_redacted_total": 0,
            "review_target": 0,
            "minimum_per_decision": 0,
            "real_redacted_by_decision": [],
            "by_channel": [],
            "recommendation_count": 0,
            "error_count": 0,
            "updated_at": "",
        }

    return {
        "status": str(report.get("status") or "unknown"),
        "ready": bool(report.get("ready_for_payment_assurance", False)),
        "row_count": _safe_int(report.get("row_count")),
        "real_redacted_total": _safe_int(report.get("real_redacted_total")),
        "pii_free_real_redacted_total": _safe_int(report.get("pii_free_real_redacted_total")),
        "review_target": _safe_int(report.get("review_target")),
        "minimum_per_decision": _safe_int(report.get("minimum_per_decision")),
        "real_redacted_by_decision": _counter_dict_to_rows(report.get("real_redacted_by_decision")),
        "by_channel": _counter_dict_to_rows(report.get("by_channel")),
        "recommendation_count": len(report.get("recommendations") or []),
        "error_count": len(report.get("errors") or []),
        "updated_at": str(report.get("generated_at") or ""),
    }


def _read_status(path: str | Path) -> dict[str, Any]:
    try:
        status_path = Path(path)
        if not status_path.exists():
            return {}
        payload = json.loads(status_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError, TypeError):
        logger.debug("Suppressed exception in src/reporting/ops_status.py", exc_info=True)
        return {}
    return payload if isinstance(payload, dict) else {}


def _counter_dict_to_rows(value: object) -> list[dict[str, int | str]]:
    if not isinstance(value, dict):
        return []
    return [
        {"name": str(name), "count": _safe_int(count)}
        for name, count in sorted(value.items(), key=lambda item: (-_safe_int(item[1]), str(item[0])))
    ]


def _safe_int(value: object) -> int:
    try:
        return int(value or 0)
    except (TypeError, ValueError):
        logger.debug("Suppressed exception in src/reporting/ops_status.py", exc_info=True)
        return 0


def _safe_text(value: object) -> str:
    text = str(value or "")[:240]
    for name in ("TAXII_PASSWORD", "TAXII_BEARER_TOKEN"):
        secret = os.getenv(name, "")
        if secret:
            text = text.replace(secret, "[redacted]")
    return text


def _safe_url(value: str) -> str:
    if not value:
        return ""
    parts = urlsplit(value)
    netloc = parts.netloc.rsplit("@", 1)[-1] if "@" in parts.netloc else parts.netloc
    return urlunsplit((parts.scheme, netloc, parts.path, "", ""))
