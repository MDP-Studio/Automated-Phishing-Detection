#!/usr/bin/env python3
"""Push a STIX 2.1 bundle into a TAXII 2.1 collection."""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from src.reporting.taxii_client import (  # noqa: E402  # agent-quality: allow: scoped lint suppression is required for import order or optional dependency compatibility
    TaxiiPushConfig,
    prepare_taxii_envelope,
    push_stix_bundle,
    write_taxii_status,
)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument("--stix", type=Path, required=True, help="STIX bundle JSON file to push")
    parser.add_argument("--base-url", default=None, help="TAXII API root URL")
    parser.add_argument("--collection-id", default=None, help="TAXII collection id")
    parser.add_argument("--objects-url", default=None, help="Full TAXII objects endpoint URL")
    parser.add_argument("--username", default=None, help="Basic-auth username")
    parser.add_argument("--password", default=None, help="Basic-auth password")
    parser.add_argument("--bearer-token", default=None, help="Bearer token")
    parser.add_argument("--timeout", type=float, default=None, help="HTTP timeout in seconds")
    parser.add_argument("--no-verify-tls", action="store_true", help="Disable TLS certificate verification")
    parser.add_argument("--dry-run", action="store_true", help="Validate the TAXII envelope without network I/O")
    parser.add_argument("--status-output", type=Path, default=None, help="Write safe push status JSON")
    args = parser.parse_args(argv)

    stix_text = args.stix.read_text(encoding="utf-8-sig")
    env_config = TaxiiPushConfig.from_env()
    config = TaxiiPushConfig(
        enabled=True,
        base_url=args.base_url if args.base_url is not None else env_config.base_url,
        collection_id=args.collection_id if args.collection_id is not None else env_config.collection_id,
        objects_url=args.objects_url if args.objects_url is not None else env_config.objects_url,
        username=args.username if args.username is not None else env_config.username,
        password=args.password if args.password is not None else env_config.password,
        bearer_token=args.bearer_token if args.bearer_token is not None else env_config.bearer_token,
        timeout_seconds=args.timeout if args.timeout is not None else env_config.timeout_seconds,
        verify_tls=not args.no_verify_tls and env_config.verify_tls,
        status_path=args.status_output or env_config.status_path,
    )

    if args.dry_run:
        envelope = prepare_taxii_envelope(stix_text)
        payload = {
            "status": "success",
            "success": True,
            "enabled": True,
            "configured": config.configured,
            "object_count": len(envelope["objects"]),
            "message": "TAXII dry run validated STIX object envelope",
        }
        if args.status_output:
            args.status_output.parent.mkdir(parents=True, exist_ok=True)
            args.status_output.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        print(f"TAXII dry run OK: {len(envelope['objects'])} STIX objects")
        return 0

    result = push_stix_bundle(stix_text, config=config)
    write_taxii_status(result, args.status_output or config.status_path)
    print(f"TAXII push {result.status}: {result.message}")
    return 0 if result.success else 1


if __name__ == "__main__":
    raise SystemExit(main())
