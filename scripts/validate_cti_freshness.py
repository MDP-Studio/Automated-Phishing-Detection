#!/usr/bin/env python3
"""Validate CTI mapping freshness and generated compatibility evidence."""
from __future__ import annotations

import argparse
import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

PROJECT_ROOT = Path(__file__).resolve().parent.parent
EXPECTED_ATTACK_VERSION = "19.1"
EXPECTED_SIGMA_SPEC_VERSION = "2.1.0"
EXPECTED_STIX_VERSION = "2.1"
EXPECTED_TAXII_VERSION = "2.1"
PASSING_TARGET_STATUSES = {"success", "skipped"}

sys.path.insert(0, str(PROJECT_ROOT))


def _load_analyzer_attack_tags() -> dict[str, list[str]]:
    from src.reporting.sigma_exporter import ANALYZER_ATTACK_TAGS

    return ANALYZER_ATTACK_TAGS


def _load_signed_compatibility_report(report_path: Path) -> dict[str, Any]:
    from scripts.cti_compatibility_report import verify_signed_compatibility_report

    return verify_signed_compatibility_report(report_path)


def validate_cti_freshness(
    *,
    project_root: Path = PROJECT_ROOT,
    report_path: Path | None = None,
) -> dict[str, Any]:
    docs_path = project_root / "docs" / "MITRE_ATTACK_MAPPING.md"
    docs_text = docs_path.read_text(encoding="utf-8")
    failures: list[str] = []
    analyzer_attack_tags = _load_analyzer_attack_tags()

    if f"v{EXPECTED_ATTACK_VERSION}" not in docs_text and f"version {EXPECTED_ATTACK_VERSION}" not in docs_text:
        failures.append(f"MITRE mapping doc must reference ATT&CK v{EXPECTED_ATTACK_VERSION}")

    docs_techniques = {match.upper() for match in re.findall(r"\bT\d{4}(?:\.\d{3})?\b", docs_text)}
    exported_techniques: set[str] = set()
    for analyzer, tags in analyzer_attack_tags.items():
        if not tags:
            failures.append(f"{analyzer} has no Sigma ATT&CK tags")
        technique_count = 0
        for tag in tags:
            if re.fullmatch(r"attack\.t\d{4}(?:\.\d{3})?", tag):
                technique_count += 1
                exported_techniques.add(tag.removeprefix("attack.").upper())
                continue
            if not re.fullmatch(r"attack\.[a-z_]+", tag):
                failures.append(f"invalid Sigma ATT&CK tag for {analyzer}: {tag}")
        if technique_count == 0:
            failures.append(f"{analyzer} has no Sigma ATT&CK technique tag")

    missing_from_doc = sorted(exported_techniques - docs_techniques)
    if missing_from_doc:
        failures.append(f"Sigma exporter tags missing from MITRE doc: {', '.join(missing_from_doc)}")

    report_status = None
    if report_path is not None:
        report = _load_signed_compatibility_report(report_path)
        report_status = report.get("overall_status")
        if report_status != "success":
            failures.append(f"CTI compatibility report status is {report_status}")
        target_statuses = {
            target.get("name"): target.get("status")
            for target in report.get("compatibility_targets", [])
        }
        for required in ("signed_export_manifest", "opencti_taxii_ingest", "sigma_splunk_conversion"):
            if target_statuses.get(required) not in PASSING_TARGET_STATUSES:
                failures.append(f"CTI target {required} is not passing: {target_statuses.get(required)}")

    status = {
        "schema_version": "cti-freshness.v1",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "status": "failed" if failures else "success",
        "expected_versions": {
            "attack": EXPECTED_ATTACK_VERSION,
            "sigma_spec": EXPECTED_SIGMA_SPEC_VERSION,
            "stix": EXPECTED_STIX_VERSION,
            "taxii": EXPECTED_TAXII_VERSION,
        },
        "analyzers_checked": len(analyzer_attack_tags),
        "exported_attack_techniques": sorted(exported_techniques),
        "report_path": str(report_path) if report_path else None,
        "report_status": report_status,
        "failures": failures,
    }
    return status


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cti-report", type=Path)
    parser.add_argument("--status-output", type=Path, default=PROJECT_ROOT / "reports" / "cti-freshness.json")
    args = parser.parse_args(argv)

    status = validate_cti_freshness(report_path=args.cti_report)
    args.status_output.parent.mkdir(parents=True, exist_ok=True)
    args.status_output.write_text(json.dumps(status, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(f"CTI freshness {status['status']}: {args.status_output}")
    for failure in status["failures"]:
        print(f"- {failure}", file=sys.stderr)
    return 0 if status["status"] == "success" else 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
