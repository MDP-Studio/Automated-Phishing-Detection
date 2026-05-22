import json

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from scripts import cti_compatibility_report
from scripts.sigma_convert_check import SigmaConversionCheck
from src.reporting.export_integrity import ExportIntegrityError, _b64encode, validate_manifest_artifacts


def _private_key_b64() -> str:
    key = Ed25519PrivateKey.generate()
    return _b64encode(key.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    ))


def _sigma_success(**overrides):
    payload = {
        "status": "success",
        "success": True,
        "backend": "splunk",
        "rules_checked": 7,
        "rules_converted": 7,
        "query_count": 7,
        "failure_count": 0,
        "failures": [],
        "started_at": "2026-05-22T00:00:00+00:00",
        "completed_at": "2026-05-22T00:00:01+00:00",
        "duration_ms": 1000,
        "converter_required": True,
    }
    payload.update(overrides)
    return SigmaConversionCheck(**payload)


def test_cti_compatibility_report_signs_multi_consumer_results(monkeypatch, tmp_path):
    monkeypatch.setattr(
        cti_compatibility_report,
        "run_sigma_conversion_check",
        lambda paths, backend_name, require_converter: _sigma_success(
            backend=backend_name,
            converter_required=require_converter,
        ),
    )

    report, report_path = cti_compatibility_report.build_cti_compatibility_report(
        output_dir=tmp_path,
        require_sigma_converter=True,
        taxii_mode="dry-run",
        export_signing_key_b64=_private_key_b64(),
        report_signing_key_b64=_private_key_b64(),
        report_key_id="unit-report-key",
    )

    verified = cti_compatibility_report.verify_signed_compatibility_report(report_path)
    targets = {target["name"]: target for target in verified["compatibility_targets"]}

    assert report["overall_status"] == "success"
    assert verified["key_id"] == "unit-report-key"
    assert targets["signed_export_manifest"]["success"] is True
    assert targets["opencti_taxii_ingest"]["consumer"] == "OpenCTI TAXII API"
    assert targets["opencti_taxii_ingest"]["details"]["mode"] == "dry-run"
    assert targets["opencti_taxii_ingest"]["details"]["object_count"] > 0
    assert targets["sigma_splunk_conversion"]["required"] is True
    assert targets["sigma_splunk_conversion"]["details"]["rules_converted"] == 7
    validate_manifest_artifacts(tmp_path / "cti_compatibility_export_manifest.json")


def test_cti_compatibility_report_signature_detects_tampering(monkeypatch, tmp_path):
    monkeypatch.setattr(
        cti_compatibility_report,
        "run_sigma_conversion_check",
        lambda paths, backend_name, require_converter: _sigma_success(),
    )
    _, report_path = cti_compatibility_report.build_cti_compatibility_report(
        output_dir=tmp_path,
        export_signing_key_b64=_private_key_b64(),
        report_signing_key_b64=_private_key_b64(),
    )
    payload = json.loads(report_path.read_text(encoding="utf-8"))
    payload["overall_status"] = "failed"
    report_path.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")

    with pytest.raises(ExportIntegrityError, match="signature verification failed"):
        cti_compatibility_report.verify_signed_compatibility_report(report_path)


def test_live_if_configured_taxii_is_optional_when_no_endpoint(monkeypatch, tmp_path):
    monkeypatch.delenv("TAXII_OBJECTS_URL", raising=False)
    monkeypatch.delenv("TAXII_BASE_URL", raising=False)
    monkeypatch.delenv("TAXII_COLLECTION_ID", raising=False)
    monkeypatch.setattr(
        cti_compatibility_report,
        "run_sigma_conversion_check",
        lambda paths, backend_name, require_converter: _sigma_success(),
    )

    report, _ = cti_compatibility_report.build_cti_compatibility_report(
        output_dir=tmp_path,
        taxii_mode="live-if-configured",
        export_signing_key_b64=_private_key_b64(),
        report_signing_key_b64=_private_key_b64(),
    )
    taxii = next(target for target in report["compatibility_targets"] if target["name"] == "opencti_taxii_ingest")

    assert report["overall_status"] == "success"
    assert taxii["status"] == "skipped"
    assert taxii["required"] is False
