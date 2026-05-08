import json

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from stix2 import Bundle, Identity

from src.reporting.export_integrity import (
    ExportIntegrityError,
    _b64encode,
    validate_manifest_artifacts,
    validate_sigma_rule,
    validate_stix_bundle,
    verify_signed_export_manifest,
    write_signed_export_manifest,
)


def _private_key_b64() -> str:
    key = Ed25519PrivateKey.generate()
    return _b64encode(key.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    ))


def _write_sample_exports(tmp_path):
    stix_path = tmp_path / "sample_iocs.json"
    sigma_path = tmp_path / "sample_rule.yml"
    identity = Identity(name="Unit Test Exporter", identity_class="organization")
    stix_path.write_text(Bundle(objects=[identity], allow_custom=True).serialize(pretty=True), encoding="utf-8")
    sigma_path.write_text(
        "\n".join([
            "title: Suspicious Payment Lure",
            "id: 68afdace-6084-48da-a4fd-4e9f015f96d2",
            "status: test",
            "logsource:",
            "  category: email",
            "detection:",
            "  selection:",
            "    subject|contains: invoice",
            "  condition: selection",
            "level: low",
            "",
        ]),
        encoding="utf-8",
    )
    return stix_path, sigma_path


def test_signed_manifest_verifies_and_validates_stix_sigma(tmp_path):
    stix_path, sigma_path = _write_sample_exports(tmp_path)
    manifest_path = tmp_path / "manifest.json"

    manifest = write_signed_export_manifest(
        [stix_path, sigma_path],
        manifest_path,
        private_key_b64=_private_key_b64(),
        key_id="unit-test",
    )
    verified = validate_manifest_artifacts(manifest_path)

    assert verified["key_id"] == "unit-test"
    assert len(manifest["artifacts"]) == 2


def test_signed_manifest_detects_tampered_artifact(tmp_path):
    stix_path, sigma_path = _write_sample_exports(tmp_path)
    manifest_path = tmp_path / "manifest.json"
    write_signed_export_manifest(
        [stix_path, sigma_path],
        manifest_path,
        private_key_b64=_private_key_b64(),
    )
    sigma_path.write_text(sigma_path.read_text(encoding="utf-8") + "\n# changed\n", encoding="utf-8")

    with pytest.raises(ExportIntegrityError, match="hash mismatch"):
        verify_signed_export_manifest(manifest_path)


def test_missing_signing_key_is_rejected(tmp_path, monkeypatch):
    monkeypatch.delenv("EXPORT_SIGNING_PRIVATE_KEY_B64", raising=False)
    stix_path, sigma_path = _write_sample_exports(tmp_path)

    with pytest.raises(ExportIntegrityError, match="required"):
        write_signed_export_manifest([stix_path, sigma_path], tmp_path / "manifest.json")


def test_stix_and_sigma_validation_reject_bad_structures(tmp_path):
    bad_stix = tmp_path / "bad_iocs.json"
    bad_sigma = tmp_path / "bad_rule.yml"
    bad_stix.write_text(json.dumps({"type": "not-bundle"}), encoding="utf-8")
    bad_sigma.write_text("title: Missing Detection\n", encoding="utf-8")

    with pytest.raises(ExportIntegrityError):
        validate_stix_bundle(bad_stix)
    with pytest.raises(ExportIntegrityError):
        validate_sigma_rule(bad_sigma)
