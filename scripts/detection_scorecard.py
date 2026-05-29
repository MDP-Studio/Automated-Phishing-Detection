#!/usr/bin/env python3
"""Build a compact detection scorecard from eval summary artifacts."""
from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

PROJECT_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_EVAL_DIR = PROJECT_ROOT / "eval_runs"
DEFAULT_OUTPUT_DIR = PROJECT_ROOT / "reports" / "detection-scorecards"
METRICS = ("precision", "recall", "f1", "accuracy")


def latest_summary(eval_dir: Path, *, exclude: Path | None = None) -> Path:
    candidates = sorted(
        (path for path in eval_dir.glob("*.summary.json") if path != exclude),
        key=lambda path: (path.stat().st_mtime, path.name),
        reverse=True,
    )
    if not candidates:
        raise FileNotFoundError(f"no eval summary files found under {eval_dir}")
    return candidates[0]


def jsonl_for_summary(summary_path: Path) -> Path:
    name = summary_path.name
    if not name.endswith(".summary.json"):
        raise ValueError(f"eval summary must end with .summary.json: {summary_path}")
    return summary_path.with_name(name.removesuffix(".summary.json") + ".jsonl")


def load_summary(path: Path) -> dict[str, Any]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ValueError(f"summary must be a JSON object: {path}")
    for projection in ("permissive", "strict"):
        if projection not in payload or not isinstance(payload[projection], dict):
            raise ValueError(f"summary is missing {projection} metrics: {path}")
    return payload


def corpus_mix(jsonl_path: Path) -> dict[str, Any]:
    labels: Counter[str] = Counter()
    channels: Counter[str] = Counter()
    if not jsonl_path.exists():
        return {"labels": {}, "channels": {}, "jsonl_available": False}
    for line_no, line in enumerate(jsonl_path.read_text(encoding="utf-8").splitlines(), start=1):
        if not line.strip():
            continue
        try:
            row = json.loads(line)
        except json.JSONDecodeError as exc:
            raise ValueError(f"invalid eval JSONL at {jsonl_path}:{line_no}: {exc}") from exc
        if not isinstance(row, dict):
            raise ValueError(f"eval JSONL row must be an object at {jsonl_path}:{line_no}")
        labels[str(row.get("true_label") or "UNKNOWN")] += 1
        channels[str(row.get("channel") or "email")] += 1
    return {
        "labels": dict(sorted(labels.items())),
        "channels": dict(sorted(channels.items())),
        "jsonl_available": True,
    }


def build_scorecard(
    *,
    summary_path: Path,
    previous_summary_path: Path | None = None,
) -> dict[str, Any]:
    summary = load_summary(summary_path)
    previous = load_summary(previous_summary_path) if previous_summary_path else None
    run_id = str(summary.get("run_id") or summary_path.name.removesuffix(".summary.json"))
    previous_run_id = str(previous.get("run_id")) if previous else None

    return {
        "schema_version": "detection-scorecard.v1",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "run_id": run_id,
        "commit_sha": summary.get("commit_sha", ""),
        "corpus_dir": summary.get("corpus_dir", ""),
        "sample_count": summary.get("sample_count", 0),
        "corpus_mix": corpus_mix(jsonl_for_summary(summary_path)),
        "metrics": {
            "permissive": _projection_metrics(summary["permissive"]),
            "strict": _projection_metrics(summary["strict"]),
        },
        "delta_from_previous": _delta(summary, previous) if previous else None,
        "previous_run_id": previous_run_id,
        "privacy": {
            "contains_raw_message_body": False,
            "contains_raw_headers": False,
            "contains_sample_text": False,
        },
    }


def _projection_metrics(payload: dict[str, Any]) -> dict[str, Any]:
    return {
        "true_positive": int(payload.get("true_positive", 0)),
        "false_positive": int(payload.get("false_positive", 0)),
        "true_negative": int(payload.get("true_negative", 0)),
        "false_negative": int(payload.get("false_negative", 0)),
        "errors": int(payload.get("errors", 0)),
        **{metric: float(payload.get(metric, 0.0)) for metric in METRICS},
    }


def _delta(current: dict[str, Any], previous: dict[str, Any]) -> dict[str, dict[str, float]]:
    result: dict[str, dict[str, float]] = {}
    for projection in ("permissive", "strict"):
        result[projection] = {
            metric: round(
                float(current[projection].get(metric, 0.0)) - float(previous[projection].get(metric, 0.0)),
                4,
            )
            for metric in METRICS
        }
    return result


def write_scorecard(scorecard: dict[str, Any], output_dir: Path) -> tuple[Path, Path]:
    output_dir.mkdir(parents=True, exist_ok=True)
    run_id = str(scorecard["run_id"])
    json_path = output_dir / f"{run_id}.scorecard.json"
    md_path = output_dir / f"{run_id}.scorecard.md"
    json_path.write_text(json.dumps(scorecard, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    md_path.write_text(render_markdown(scorecard), encoding="utf-8")
    return json_path, md_path


def render_markdown(scorecard: dict[str, Any]) -> str:
    lines = [
        "# Detection Scorecard",
        "",
        f"Run: `{scorecard['run_id']}`",
        f"Commit: `{scorecard.get('commit_sha') or 'unknown'}`",
        f"Samples: `{scorecard.get('sample_count', 0)}`",
        f"Previous run: `{scorecard.get('previous_run_id') or 'none'}`",
        "",
        "## Corpus Mix",
        "",
        f"- Labels: `{scorecard['corpus_mix']['labels']}`",
        f"- Channels: `{scorecard['corpus_mix']['channels']}`",
        "",
        "## Metrics",
        "",
        "| Projection | Precision | Recall | F1 | Accuracy | TP | FP | TN | FN | Errors |",
        "| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |",
    ]
    for projection in ("permissive", "strict"):
        metrics = scorecard["metrics"][projection]
        lines.append(
            "| "
            + " | ".join(
                [
                    projection,
                    f"{metrics['precision']:.4f}",
                    f"{metrics['recall']:.4f}",
                    f"{metrics['f1']:.4f}",
                    f"{metrics['accuracy']:.4f}",
                    str(metrics["true_positive"]),
                    str(metrics["false_positive"]),
                    str(metrics["true_negative"]),
                    str(metrics["false_negative"]),
                    str(metrics["errors"]),
                ]
            )
            + " |"
        )
    if scorecard["delta_from_previous"]:
        lines.extend(["", "## Delta From Previous", ""])
        for projection, deltas in scorecard["delta_from_previous"].items():
            rendered = ", ".join(f"{metric}={value:+.4f}" for metric, value in deltas.items())
            lines.append(f"- `{projection}`: {rendered}")
    lines.extend([
        "",
        "Privacy: scorecards include labels, channels, counts, and metrics only. "
        "They do not include raw bodies, raw headers, or sample text.",
        "",
    ])
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--eval-dir", type=Path, default=DEFAULT_EVAL_DIR)
    parser.add_argument("--summary", type=Path)
    parser.add_argument("--previous-summary", type=Path)
    parser.add_argument("--output-dir", type=Path, default=DEFAULT_OUTPUT_DIR)
    args = parser.parse_args(argv)

    summary_path = args.summary or latest_summary(args.eval_dir)
    previous_path = args.previous_summary
    if previous_path is None:
        candidates = sorted(
            (path for path in args.eval_dir.glob("*.summary.json") if path != summary_path),
            key=lambda path: path.stat().st_mtime,
        )
        previous_path = candidates[-1] if candidates else None
        if previous_path is None:
            print("No previous eval summary found; delta section omitted.", file=sys.stderr)
    scorecard = build_scorecard(summary_path=summary_path, previous_summary_path=previous_path)
    json_path, md_path = write_scorecard(scorecard, args.output_dir)
    print(f"Detection scorecard written: {json_path}")
    print(f"Detection scorecard markdown: {md_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
