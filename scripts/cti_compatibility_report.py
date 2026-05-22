#!/usr/bin/env python3
"""Build a signed CTI compatibility report for STIX, TAXII, and Sigma consumers."""
from __future__ import annotations

import argparse
import json
import logging
import os
import sys
import time
from dataclasses import replace
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from scripts.sigma_convert_check import (  # noqa: E402  # agent-quality: allow
    run_sigma_conversion_check,
    write_sigma_conversion_status,
)
from src.models import (  # noqa: E402  # agent-quality: allow
    AnalyzerResult,
    ExtractedURL,
    PipelineResult,
    URLSource,
    Verdict,
)
from src.reporting.export_integrity import (  # noqa: E402  # agent-quality: allow
    ExportIntegrityError,
    _b64decode,
    _b64encode,
    validate_manifest_artifacts,
    write_signed_export_manifest,
)
from src.reporting.ioc_exporter import IOCExporter  # noqa: E402  # agent-quality: allow
from src.reporting.sigma_exporter import SigmaExporter  # noqa: E402  # agent-quality: allow
from src.reporting.taxii_client import (  # noqa: E402  # agent-quality: allow
    TaxiiPushConfig,
    prepare_taxii_envelope,
    push_stix_bundle,
)


logger = logging.getLogger(__name__)
REPORT_SCHEMA_VERSION = 1
DEFAULT_OUTPUT_DIR = PROJECT_ROOT / "reports" / "cti-compatibility"
DEFAULT_REPORT_NAME = "cti_compatibility_report.json"
DEFAULT_EXPORT_MANIFEST_NAME = "cti_compatibility_export_manifest.json"
DEFAULT_SIGMA_STATUS_NAME = "sigma_conversion_status.json"
DEFAULT_STIX_NAME = "cti_compatibility_iocs.json"
DEFAULT_SIGMA_NAME = "cti_compatibility_campaign_rule.yml"
PASSING_STATUS = {"success", "skipped"}


def build_cti_compatibility_report(
    *,
    output_dir: Path = DEFAULT_OUTPUT_DIR,
    sigma_backend: str = "splunk",
    require_sigma_converter: bool = False,
    taxii_mode: str = "dry-run",
    report_ref: str | None = None,
    export_signing_key_b64: str | None = None,
    report_signing_key_b64: str | None = None,
    report_key_id: str | None = None,
) -> tuple[dict[str, Any], Path]:
    """Run repeatable CTI consumer checks and write a signed report artifact."""
    started_at = _now_iso()
    started = time.perf_counter()
    output_dir.mkdir(parents=True, exist_ok=True)

    sample = _sample_pipeline_result()
    stix_path = output_dir / DEFAULT_STIX_NAME
    sigma_path = output_dir / DEFAULT_SIGMA_NAME
    manifest_path = output_dir / DEFAULT_EXPORT_MANIFEST_NAME
    sigma_status_path = output_dir / DEFAULT_SIGMA_STATUS_NAME

    stix_path.write_text(
        IOCExporter(organization_name="PhishAnalyze CTI Compatibility").export_stix(sample),
        encoding="utf-8",
    )
    sigma_path.write_text(
        SigmaExporter(author="PhishAnalyze CTI Compatibility").export_campaign_rule(sample),
        encoding="utf-8",
    )

    checks = []
    export_key = export_signing_key_b64 or os.getenv("CTI_COMPAT_EXPORT_SIGNING_PRIVATE_KEY_B64")
    if not export_key:
        export_key = _generate_private_key_b64()
    write_signed_export_manifest(
        [stix_path, sigma_path],
        manifest_path,
        private_key_b64=export_key,
        key_id=os.getenv("CTI_COMPAT_EXPORT_SIGNING_KEY_ID", "cti-compatibility-export"),
    )
    checks.append(_run_signed_export_check(manifest_path))
    checks.append(_run_taxii_check(stix_path, taxii_mode=taxii_mode))
    checks.append(_run_sigma_check(
        sigma_path,
        sigma_status_path,
        backend=sigma_backend,
        require_converter=require_sigma_converter,
    ))

    completed_at = _now_iso()
    unsigned_report = {
        "schema_version": REPORT_SCHEMA_VERSION,
        "generated_at": completed_at,
        "started_at": started_at,
        "duration_ms": max(0, round((time.perf_counter() - started) * 1000)),
        "project": "PhishAnalyze / PayShield",
        "report_ref": report_ref or _default_report_ref(),
        "overall_status": _overall_status(checks),
        "summary": _summary(checks),
        "compatibility_targets": checks,
        "artifacts": {
            "stix_bundle": _relative_path(stix_path),
            "sigma_campaign_rule": _relative_path(sigma_path),
            "signed_export_manifest": _relative_path(manifest_path),
            "sigma_conversion_status": _relative_path(sigma_status_path),
        },
    }
    signed_report = sign_compatibility_report(
        unsigned_report,
        private_key_b64=report_signing_key_b64,
        key_id=report_key_id,
    )
    report_path = output_dir / DEFAULT_REPORT_NAME
    report_path.write_text(json.dumps(signed_report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    verify_signed_compatibility_report(report_path)
    return signed_report, report_path


def sign_compatibility_report(
    report: dict[str, Any],
    *,
    private_key_b64: str | None = None,
    key_id: str | None = None,
) -> dict[str, Any]:
    """Attach an Ed25519 signature to a CTI compatibility report."""
    private_key = _load_or_generate_private_key(
        private_key_b64 or os.getenv("CTI_COMPAT_REPORT_SIGNING_PRIVATE_KEY_B64")
    )
    public_key_b64 = _b64encode(private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    ))
    payload = {
        **report,
        "signature_algorithm": "Ed25519",
        "key_id": (key_id or os.getenv("CTI_COMPAT_REPORT_SIGNING_KEY_ID") or "cti-compatibility-report").strip(),
        "public_key_b64": public_key_b64,
    }
    signature = private_key.sign(_canonical_report_bytes(payload))
    return {**payload, "signature": _b64encode(signature)}


def verify_signed_compatibility_report(report_path: str | Path, *, public_key_b64: str | None = None) -> dict[str, Any]:
    """Verify a signed CTI compatibility report JSON artifact."""
    path = Path(report_path)
    report = json.loads(path.read_text(encoding="utf-8"))
    if report.get("schema_version") != REPORT_SCHEMA_VERSION:
        raise ExportIntegrityError("Unsupported CTI compatibility report schema version")
    if report.get("signature_algorithm") != "Ed25519":
        raise ExportIntegrityError("Unsupported CTI compatibility report signature algorithm")
    signature_b64 = str(report.get("signature") or "")
    if not signature_b64:
        raise ExportIntegrityError("CTI compatibility report is missing a signature")
    pinned_public_key = (
        public_key_b64
        or os.getenv("CTI_COMPAT_REPORT_SIGNING_PUBLIC_KEY_B64")
        or report.get("public_key_b64")
    )
    if not pinned_public_key:
        raise ExportIntegrityError("A public key is required to verify this CTI compatibility report")
    payload = {key: value for key, value in report.items() if key != "signature"}
    public_key = Ed25519PublicKey.from_public_bytes(_b64decode(pinned_public_key))
    try:
        public_key.verify(_b64decode(signature_b64), _canonical_report_bytes(payload))
    except Exception as exc:
        raise ExportIntegrityError("CTI compatibility report signature verification failed") from exc
    return report


def _run_signed_export_check(manifest_path: Path) -> dict[str, Any]:
    started_at = _now_iso()
    started = time.perf_counter()
    try:
        manifest = validate_manifest_artifacts(manifest_path)
        return _target(
            name="signed_export_manifest",
            target_type="stix_sigma_export",
            consumer="portable filesystem consumers",
            status="success",
            success=True,
            required=True,
            started_at=started_at,
            started=started,
            details={
                "manifest": _relative_path(manifest_path),
                "artifacts_checked": len(manifest.get("artifacts", [])),
                "signature_algorithm": manifest.get("signature_algorithm"),
                "key_id": manifest.get("key_id"),
            },
        )
    except Exception as exc:
        logger.warning("Signed STIX/Sigma export validation failed: %s", _safe_reason(exc))
        return _target(
            name="signed_export_manifest",
            target_type="stix_sigma_export",
            consumer="portable filesystem consumers",
            status="failed",
            success=False,
            required=True,
            started_at=started_at,
            started=started,
            details={"reason": _safe_reason(exc)},
        )


def _run_taxii_check(stix_path: Path, *, taxii_mode: str) -> dict[str, Any]:
    started_at = _now_iso()
    started = time.perf_counter()
    stix_text = stix_path.read_text(encoding="utf-8-sig")
    mode = taxii_mode.lower()
    required = mode == "live"

    try:
        if mode == "dry-run":
            envelope = prepare_taxii_envelope(stix_text)
            return _target(
                name="opencti_taxii_ingest",
                target_type="taxii_2_1_add_objects",
                consumer="OpenCTI TAXII API",
                status="success",
                success=True,
                required=True,
                started_at=started_at,
                started=started,
                details={
                    "mode": "dry-run",
                    "object_count": len(envelope["objects"]),
                    "message": "TAXII Add Objects envelope validated without network I/O",
                },
            )

        env_config = TaxiiPushConfig.from_env()
        if mode == "live-if-configured" and not env_config.configured:
            return _target(
                name="opencti_taxii_ingest",
                target_type="taxii_2_1_add_objects",
                consumer="OpenCTI TAXII API",
                status="skipped",
                success=True,
                required=False,
                started_at=started_at,
                started=started,
                details={
                    "mode": "live-if-configured",
                    "configured": False,
                    "message": "No TAXII endpoint configured in CI environment",
                },
            )
        live_config = replace(env_config, enabled=True)
        result = push_stix_bundle(stix_text, config=live_config)
        payload = result.to_dict()
        payload["mode"] = mode
        return _target(
            name="opencti_taxii_ingest",
            target_type="taxii_2_1_add_objects",
            consumer="OpenCTI TAXII API",
            status=result.status,
            success=result.success,
            required=required,
            started_at=started_at,
            started=started,
            details=payload,
        )
    except Exception as exc:
        logger.warning("OpenCTI TAXII compatibility check failed: %s", _safe_reason(exc))
        return _target(
            name="opencti_taxii_ingest",
            target_type="taxii_2_1_add_objects",
            consumer="OpenCTI TAXII API",
            status="failed",
            success=False,
            required=required,
            started_at=started_at,
            started=started,
            details={"mode": mode, "reason": _safe_reason(exc)},
        )


def _run_sigma_check(
    sigma_path: Path,
    status_path: Path,
    *,
    backend: str,
    require_converter: bool,
) -> dict[str, Any]:
    started_at = _now_iso()
    started = time.perf_counter()
    try:
        check = run_sigma_conversion_check(
            [sigma_path, PROJECT_ROOT / "sigma_rules"],
            backend_name=backend,
            require_converter=require_converter,
        )
        write_sigma_conversion_status(check, status_path)
        return _target(
            name=f"sigma_{backend}_conversion",
            target_type="sigma_backend_conversion",
            consumer=f"pySigma {backend} backend",
            status=check.status,
            success=check.success,
            required=require_converter,
            started_at=started_at,
            started=started,
            details={
                **check.to_dict(),
                "status_output": _relative_path(status_path),
            },
        )
    except Exception as exc:
        logger.warning("Sigma backend compatibility check failed: %s", _safe_reason(exc))
        return _target(
            name=f"sigma_{backend}_conversion",
            target_type="sigma_backend_conversion",
            consumer=f"pySigma {backend} backend",
            status="failed",
            success=False,
            required=require_converter,
            started_at=started_at,
            started=started,
            details={"reason": _safe_reason(exc)},
        )


def _target(
    *,
    name: str,
    target_type: str,
    consumer: str,
    status: str,
    success: bool,
    required: bool,
    started_at: str,
    started: float,
    details: dict[str, Any],
) -> dict[str, Any]:
    return {
        "name": name,
        "type": target_type,
        "consumer": consumer,
        "status": status,
        "success": success,
        "required": required,
        "started_at": started_at,
        "completed_at": _now_iso(),
        "duration_ms": max(0, round((time.perf_counter() - started) * 1000)),
        "details": details,
    }


def _sample_pipeline_result() -> PipelineResult:
    return PipelineResult(
        email_id="cti-compatibility-smoke",
        verdict=Verdict.LIKELY_PHISHING,
        overall_score=0.82,
        overall_confidence=0.88,
        analyzer_results={
            "header_analysis": AnalyzerResult(
                analyzer_name="header_analysis",
                risk_score=0.72,
                confidence=0.84,
                details={"from_reply_to_mismatch": True},
            ),
            "url_reputation": AnalyzerResult(
                analyzer_name="url_reputation",
                risk_score=0.78,
                confidence=0.86,
                details={"threat": "credential_phishing"},
            ),
            "nlp_intent": AnalyzerResult(
                analyzer_name="nlp_intent",
                risk_score=0.76,
                confidence=0.83,
                details={"intent_classification": {"category": "bec_wire_fraud", "confidence": 0.83}},
            ),
        },
        extracted_urls=[
            ExtractedURL(
                url="https://payroll-review.example.test/login/oauth",
                source=URLSource.BODY_HTML,
                source_detail="anchor",
            )
        ],
        iocs={
            "headers": {
                "from_address": "accounts@payroll-review.example.test",
                "subject": "Urgent invoice payment portal update",
            },
            "malicious_urls": ["https://payroll-review.example.test/login/oauth"],
            "malicious_domains": ["payroll-review.example.test"],
            "malicious_ips": ["203.0.113.10"],
            "file_hashes": {"md5": "d41d8cd98f00b204e9800998ecf8427e"},
        },
        reasoning="Compatibility smoke sample with URL, domain, IP, hash, and BEC intent signals.",
    )


def _overall_status(checks: list[dict[str, Any]]) -> str:
    required_failures = [
        check for check in checks
        if check.get("required") and (not check.get("success") or check.get("status") not in PASSING_STATUS)
    ]
    return "failed" if required_failures else "success"


def _summary(checks: list[dict[str, Any]]) -> dict[str, int]:
    return {
        "checks_total": len(checks),
        "checks_successful": sum(1 for check in checks if check.get("success")),
        "checks_required": sum(1 for check in checks if check.get("required")),
        "required_failures": sum(
            1 for check in checks
            if check.get("required") and (not check.get("success") or check.get("status") not in PASSING_STATUS)
        ),
    }


def _load_or_generate_private_key(value: str | None) -> Ed25519PrivateKey:
    raw = (value or "").strip()
    if not raw:
        return Ed25519PrivateKey.generate()
    if raw.startswith("-----BEGIN"):
        key = serialization.load_pem_private_key(raw.encode("utf-8"), password=None)
        if not isinstance(key, Ed25519PrivateKey):
            raise ExportIntegrityError("CTI compatibility report signing key must be Ed25519")
        return key
    return Ed25519PrivateKey.from_private_bytes(_b64decode(raw))


def _generate_private_key_b64() -> str:
    key = Ed25519PrivateKey.generate()
    return _b64encode(key.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    ))


def _canonical_report_bytes(payload: dict[str, Any]) -> bytes:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")


def _default_report_ref() -> str:
    for name in ("GITHUB_SHA", "GIT_COMMIT", "SOURCE_VERSION"):
        value = os.getenv(name, "").strip()
        if value:
            return value
    return "local"


def _relative_path(path: Path) -> str:
    try:
        return path.resolve().relative_to(PROJECT_ROOT).as_posix()
    except ValueError:  # agent-quality: allow: report absolute paths for temp directories outside repo
        return path.resolve().as_posix()


def _safe_reason(exc: Exception) -> str:
    message = str(exc) or exc.__class__.__name__
    for key in (
        "TAXII_PASSWORD",
        "TAXII_BEARER_TOKEN",
        "CTI_COMPAT_REPORT_SIGNING_PRIVATE_KEY_B64",
        "CTI_COMPAT_EXPORT_SIGNING_PRIVATE_KEY_B64",
    ):
        secret = os.getenv(key, "")
        if secret:
            message = message.replace(secret, "[redacted]")
    return message[:300]


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument("--output-dir", type=Path, default=DEFAULT_OUTPUT_DIR)
    parser.add_argument("--sigma-backend", default="splunk", choices=["splunk"])
    parser.add_argument("--require-sigma-converter", action="store_true")
    parser.add_argument("--taxii-mode", choices=["dry-run", "live", "live-if-configured"], default="dry-run")
    parser.add_argument("--report-ref", default=None)
    args = parser.parse_args(argv)

    report, report_path = build_cti_compatibility_report(
        output_dir=args.output_dir,
        sigma_backend=args.sigma_backend,
        require_sigma_converter=args.require_sigma_converter,
        taxii_mode=args.taxii_mode,
        report_ref=args.report_ref,
    )
    print(f"CTI compatibility report {report['overall_status']}: {report_path}")
    for target in report["compatibility_targets"]:
        print(f"{target['status'].upper()} {target['name']} -> {target['consumer']}")
    return 0 if report["overall_status"] == "success" else 1


if __name__ == "__main__":
    raise SystemExit(main())
