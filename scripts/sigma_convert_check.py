#!/usr/bin/env python3
"""Validate Sigma rules with pySigma conversion in CI."""
from __future__ import annotations

import argparse
import json
import sys
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from src.reporting.export_integrity import ExportIntegrityError, validate_sigma_rule  # noqa: E402


DEFAULT_STATUS_PATH = PROJECT_ROOT / "data" / "sigma_conversion_status.json"


@dataclass(frozen=True)
class SigmaConversionCheck:
    status: str
    success: bool
    backend: str
    rules_checked: int
    rules_converted: int
    query_count: int
    failure_count: int
    failures: list[dict[str, str]]
    started_at: str
    completed_at: str
    duration_ms: int
    converter_required: bool

    def to_dict(self) -> dict[str, Any]:
        return {
            "status": self.status,
            "success": self.success,
            "backend": self.backend,
            "rules_checked": self.rules_checked,
            "rules_converted": self.rules_converted,
            "query_count": self.query_count,
            "failure_count": self.failure_count,
            "failures": self.failures[:20],
            "started_at": self.started_at,
            "completed_at": self.completed_at,
            "duration_ms": self.duration_ms,
            "converter_required": self.converter_required,
        }


def run_sigma_conversion_check(
    paths: list[Path] | None = None,
    *,
    backend_name: str = "splunk",
    require_converter: bool = False,
) -> SigmaConversionCheck:
    started_at = _now_iso()
    started = time.perf_counter()
    rule_paths = _collect_rule_paths(paths)
    failures: list[dict[str, str]] = []
    rules_converted = 0
    query_count = 0

    try:
        backend = _load_backend(backend_name)
    except Exception as exc:
        if require_converter:
            failures.append({"path": "converter", "reason": _safe_reason(exc)})
            return _finish(
                "failed",
                False,
                backend_name,
                len(rule_paths),
                rules_converted,
                query_count,
                failures,
                started_at,
                started,
                require_converter,
            )
        return _finish(
            "skipped",
            True,
            backend_name,
            len(rule_paths),
            0,
            0,
            [{"path": "converter", "reason": _safe_reason(exc)}],
            started_at,
            started,
            require_converter,
        )

    for path in rule_paths:
        rel = _relative_path(path)
        try:
            validate_sigma_rule(path)
            queries = _convert_rule(path, backend)
            if not queries:
                raise RuntimeError("converter returned no queries")
            rules_converted += 1
            query_count += len(queries)
        except Exception as exc:
            failures.append({"path": rel, "reason": _safe_reason(exc)})

    return _finish(
        "success" if not failures else "failed",
        not failures,
        backend_name,
        len(rule_paths),
        rules_converted,
        query_count,
        failures,
        started_at,
        started,
        require_converter,
    )


def write_sigma_conversion_status(check: SigmaConversionCheck, path: str | Path = DEFAULT_STATUS_PATH) -> Path:
    status_path = Path(path)
    status_path.parent.mkdir(parents=True, exist_ok=True)
    status_path.write_text(json.dumps(check.to_dict(), indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return status_path


def _load_backend(backend_name: str):
    if backend_name != "splunk":
        raise ValueError(f"unsupported Sigma backend: {backend_name}")
    from sigma.backends.splunk import SplunkBackend

    return SplunkBackend()


def _convert_rule(path: Path, backend) -> list[str]:
    from sigma.collection import SigmaCollection

    collection = SigmaCollection.from_yaml(path.read_text(encoding="utf-8"))
    return list(backend.convert(collection))


def _collect_rule_paths(paths: list[Path] | None) -> list[Path]:
    if paths:
        candidates = []
        for path in paths:
            if path.is_dir():
                candidates.extend(sorted(path.glob("*.yml")))
                candidates.extend(sorted(path.glob("*.yaml")))
            else:
                candidates.append(path)
    else:
        candidates = sorted((PROJECT_ROOT / "sigma_rules").glob("*.yml"))
    return [path for path in candidates if path.name.lower() != "readme.md"]


def _finish(
    status: str,
    success: bool,
    backend: str,
    rules_checked: int,
    rules_converted: int,
    query_count: int,
    failures: list[dict[str, str]],
    started_at: str,
    started: float,
    require_converter: bool,
) -> SigmaConversionCheck:
    return SigmaConversionCheck(
        status=status,
        success=success,
        backend=backend,
        rules_checked=rules_checked,
        rules_converted=rules_converted,
        query_count=query_count,
        failure_count=len(failures),
        failures=failures,
        started_at=started_at,
        completed_at=_now_iso(),
        duration_ms=max(0, round((time.perf_counter() - started) * 1000)),
        converter_required=require_converter,
    )


def _relative_path(path: Path) -> str:
    try:
        return path.resolve().relative_to(PROJECT_ROOT).as_posix()
    except ValueError:
        return path.name


def _safe_reason(exc: Exception) -> str:
    reason = str(exc) or exc.__class__.__name__
    if isinstance(exc, ExportIntegrityError):
        reason = str(exc)
    return reason[:300]


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument("paths", nargs="*", type=Path, help="Sigma rule files or directories")
    parser.add_argument("--backend", default="splunk", choices=["splunk"])
    parser.add_argument("--require-converter", action="store_true")
    parser.add_argument("--status-output", type=Path, default=DEFAULT_STATUS_PATH)
    args = parser.parse_args(argv)

    check = run_sigma_conversion_check(
        args.paths or None,
        backend_name=args.backend,
        require_converter=args.require_converter,
    )
    write_sigma_conversion_status(check, args.status_output)
    print(
        "Sigma conversion "
        f"{check.status}: {check.rules_converted}/{check.rules_checked} rules, "
        f"{check.query_count} queries via {check.backend}"
    )
    for failure in check.failures:
        print(f"FAIL {failure['path']}: {failure['reason']}", file=sys.stderr)
    return 0 if check.success else 1


if __name__ == "__main__":
    raise SystemExit(main())
