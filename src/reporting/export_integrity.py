"""Signed manifest support for shareable STIX and Sigma export artifacts."""
from __future__ import annotations
import logging

import base64
import hashlib
import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable

import yaml
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

logger = logging.getLogger(__name__)

EXPORT_MANIFEST_VERSION = 1


class ExportIntegrityError(ValueError):
    """Raised when export artifacts cannot be signed or validated."""


def write_signed_export_manifest(
    artifact_paths: Iterable[str | Path],
    manifest_path: str | Path,
    *,
    private_key_b64: str | None = None,
    key_id: str | None = None,
    created_at: str | None = None,
) -> dict:
    """Write an Ed25519-signed manifest for exported STIX/Sigma files."""
    manifest = Path(manifest_path)
    manifest.parent.mkdir(parents=True, exist_ok=True)
    private_key = _load_private_key(private_key_b64 or os.getenv("EXPORT_SIGNING_PRIVATE_KEY_B64", ""))
    public_key_b64 = _b64encode(private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    ))
    artifacts = [
        _artifact_entry(Path(path), manifest.parent)
        for path in artifact_paths
        if Path(path).exists()
    ]
    if not artifacts:
        raise ExportIntegrityError("No export artifacts were available for signing")
    payload = {
        "manifest_version": EXPORT_MANIFEST_VERSION,
        "created_at": created_at or datetime.now(timezone.utc).isoformat(),
        "signature_algorithm": "Ed25519",
        "key_id": (key_id or os.getenv("EXPORT_SIGNING_KEY_ID") or "local-export-key").strip(),
        "public_key_b64": public_key_b64,
        "artifacts": sorted(artifacts, key=lambda item: item["path"]),
    }
    signature = private_key.sign(_canonical_manifest_bytes(payload))
    signed = {**payload, "signature": _b64encode(signature)}
    manifest.write_text(json.dumps(signed, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return signed


def verify_signed_export_manifest(
    manifest_path: str | Path,
    *,
    public_key_b64: str | None = None,
) -> dict:
    """Verify a signed export manifest and every referenced artifact hash."""
    manifest_path = Path(manifest_path)
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    if manifest.get("manifest_version") != EXPORT_MANIFEST_VERSION:
        raise ExportIntegrityError("Unsupported export manifest version")
    if manifest.get("signature_algorithm") != "Ed25519":
        raise ExportIntegrityError("Unsupported export manifest signature algorithm")
    signature_b64 = str(manifest.get("signature") or "")
    if not signature_b64:
        raise ExportIntegrityError("Export manifest is missing a signature")
    pinned_public_key = public_key_b64 or os.getenv("EXPORT_SIGNING_PUBLIC_KEY_B64", "") or manifest.get("public_key_b64")
    if not pinned_public_key:
        raise ExportIntegrityError("A public key is required to verify this export manifest")

    payload = {key: value for key, value in manifest.items() if key != "signature"}
    public_key = Ed25519PublicKey.from_public_bytes(_b64decode(pinned_public_key))
    try:
        public_key.verify(_b64decode(signature_b64), _canonical_manifest_bytes(payload))
    except Exception as exc:
        raise ExportIntegrityError("Export manifest signature verification failed") from exc

    base_dir = manifest_path.parent.resolve()
    for artifact in manifest.get("artifacts", []):
        artifact_path = _safe_artifact_path(base_dir, artifact.get("path"))
        data = artifact_path.read_bytes()
        sha256 = hashlib.sha256(data).hexdigest()
        if sha256 != artifact.get("sha256"):
            raise ExportIntegrityError(f"Artifact hash mismatch: {artifact.get('path')}")
        if len(data) != int(artifact.get("size_bytes", -1)):
            raise ExportIntegrityError(f"Artifact size mismatch: {artifact.get('path')}")
    return manifest


def validate_stix_bundle(path: str | Path) -> None:
    """Parse a STIX bundle and reject malformed export content."""
    import stix2

    data = json.loads(Path(path).read_text(encoding="utf-8"))
    if data.get("type") != "bundle":
        raise ExportIntegrityError(f"STIX artifact is not a bundle: {path}")
    stix2.parse(data, allow_custom=True)


def validate_sigma_rule(path: str | Path) -> None:
    """Check the structural fields required by a Sigma rule export."""
    documents = [doc for doc in yaml.safe_load_all(Path(path).read_text(encoding="utf-8")) if doc]
    if not documents:
        raise ExportIntegrityError(f"Sigma artifact is empty: {path}")
    for doc in documents:
        if not isinstance(doc, dict):
            raise ExportIntegrityError(f"Sigma document is not a mapping: {path}")
        for key in ("title", "id", "status", "logsource", "detection"):
            if key not in doc:
                raise ExportIntegrityError(f"Sigma rule missing {key}: {path}")
        detection = doc.get("detection")
        if not isinstance(detection, dict) or not detection.get("condition"):
            raise ExportIntegrityError(f"Sigma rule missing detection condition: {path}")


def validate_manifest_artifacts(manifest_path: str | Path, *, public_key_b64: str | None = None) -> dict:
    """Verify a manifest, then parse STIX JSON and Sigma YAML artifacts."""
    manifest = verify_signed_export_manifest(manifest_path, public_key_b64=public_key_b64)
    base_dir = Path(manifest_path).parent.resolve()
    for artifact in manifest.get("artifacts", []):
        artifact_path = _safe_artifact_path(base_dir, artifact.get("path"))
        suffix = artifact_path.suffix.lower()
        media_type = str(artifact.get("media_type") or "")
        if suffix == ".json" and "stix" in media_type:
            validate_stix_bundle(artifact_path)
        elif suffix in {".yml", ".yaml"}:
            validate_sigma_rule(artifact_path)
    return manifest


def _artifact_entry(path: Path, manifest_dir: Path) -> dict:
    data = path.read_bytes()
    try:
        rel_path = path.resolve().relative_to(manifest_dir.resolve())
    except ValueError:
        logger.debug("Suppressed exception in src/reporting/export_integrity.py", exc_info=True)
        rel_path = Path(path.name)
    return {
        "path": rel_path.as_posix(),
        "sha256": hashlib.sha256(data).hexdigest(),
        "size_bytes": len(data),
        "media_type": _media_type_for(path),
    }


def _media_type_for(path: Path) -> str:
    name = path.name.lower()
    if name.endswith("_iocs.json") or "stix" in name:
        return "application/stix+json"
    if name.endswith(".yml") or name.endswith(".yaml"):
        return "application/sigma+yaml"
    return "application/octet-stream"


def _canonical_manifest_bytes(payload: dict) -> bytes:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")


def _load_private_key(value: str) -> Ed25519PrivateKey:
    raw = (value or "").strip()
    if not raw:
        raise ExportIntegrityError(
            "EXPORT_SIGNING_PRIVATE_KEY_B64 is required for shareable STIX/Sigma file exports"
        )
    if raw.startswith("-----BEGIN"):
        key = serialization.load_pem_private_key(raw.encode("utf-8"), password=None)
        if not isinstance(key, Ed25519PrivateKey):
            raise ExportIntegrityError("Export signing key must be an Ed25519 private key")
        return key
    return Ed25519PrivateKey.from_private_bytes(_b64decode(raw))


def _safe_artifact_path(base_dir: Path, raw_path: object) -> Path:
    if not raw_path:
        raise ExportIntegrityError("Manifest artifact path is missing")
    candidate = (base_dir / str(raw_path)).resolve()
    try:
        candidate.relative_to(base_dir)
    except ValueError as exc:
        raise ExportIntegrityError(f"Manifest artifact path escapes export directory: {raw_path}") from exc
    if not candidate.exists():
        raise ExportIntegrityError(f"Manifest artifact is missing: {raw_path}")
    return candidate


def _b64encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def _b64decode(value: str) -> bytes:
    raw = value.strip().encode("ascii")
    raw += b"=" * ((4 - len(raw) % 4) % 4)
    return base64.urlsafe_b64decode(raw)
