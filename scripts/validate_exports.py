#!/usr/bin/env python3
"""Validate signed STIX/Sigma export manifests."""
from __future__ import annotations

import argparse
import sys
import tempfile
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from stix2 import Bundle, Identity

from src.reporting.export_integrity import (
    ExportIntegrityError,
    _b64encode,
    validate_manifest_artifacts,
    write_signed_export_manifest,
)


def _self_test() -> None:
    private_key = Ed25519PrivateKey.generate()
    private_b64 = _b64encode(private_key.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    ))
    with tempfile.TemporaryDirectory(prefix="export-integrity-") as tmp:
        base = Path(tmp)
        stix_path = base / "sample_iocs.json"
        sigma_path = base / "sample_rule.yml"
        manifest_path = base / "sample_export_manifest.json"
        identity = Identity(name="Export Integrity Self Test", identity_class="organization")
        stix_path.write_text(Bundle(objects=[identity], allow_custom=True).serialize(pretty=True), encoding="utf-8")
        sigma_path.write_text(
            "\n".join([
                "title: Export Integrity Self Test",
                "id: 8edbcaa8-29a5-4fb3-8f07-76bffde99261",
                "status: test",
                "logsource:",
                "  category: email",
                "detection:",
                "  selection:",
                "    subject|contains: test",
                "  condition: selection",
                "level: low",
                "",
            ]),
            encoding="utf-8",
        )
        write_signed_export_manifest(
            [stix_path, sigma_path],
            manifest_path,
            private_key_b64=private_b64,
            key_id="ci-self-test",
        )
        validate_manifest_artifacts(manifest_path)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, help="Signed export manifest JSON to validate.")
    parser.add_argument("--public-key-b64", default=None, help="Pinned Ed25519 public key in base64url form.")
    parser.add_argument("--self-test", action="store_true", help="Generate and validate a temporary signed export.")
    args = parser.parse_args()

    try:
        if args.self_test:
            _self_test()
            print("Export integrity self-test passed.")
            return 0
        if not args.manifest:
            parser.error("--manifest is required unless --self-test is used")
        manifest = validate_manifest_artifacts(args.manifest, public_key_b64=args.public_key_b64)
        print(
            "Export manifest valid: "
            f"{args.manifest} ({len(manifest.get('artifacts', []))} artifacts)"
        )
        return 0
    except ExportIntegrityError as exc:
        print(f"Export validation failed: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
