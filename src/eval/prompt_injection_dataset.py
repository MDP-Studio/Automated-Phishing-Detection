"""Build a shared prompt-injection ML dataset.

This dataset is intentionally separate from the PhishAnalyze phishing model and
the PayShield payment-decision model. It trains hostile-input recognition for
emails that try to control AI assistants, tools, prompts, or exfiltration
actions.
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import itertools
import json
import random
import re
from collections import Counter
from dataclasses import asdict, dataclass
from email import policy
from email.message import Message
from email.parser import BytesParser
from pathlib import Path
from typing import Iterator, Optional


PROJECT_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_LLMMAIL_DIR = (
    PROJECT_ROOT
    / "data"
    / "corpora"
    / "huggingface"
    / "microsoft__llmail-inject-challenge"
    / "data"
)
DEFAULT_CLEAN_CORPUS_DIR = PROJECT_ROOT / "data" / "eval_corpus_full_no_oversample"
DEFAULT_OUTPUT_DIR = PROJECT_ROOT / "data" / "prompt_injection_corpus"
DEFAULT_OUTPUT_JSONL = DEFAULT_OUTPUT_DIR / "prompt_injection_ml.jsonl"

ATTACK_LABEL = "PROMPT_INJECTION"
CLEAN_LABEL = "CLEAN"
ALLOWED_LABELS = {ATTACK_LABEL, CLEAN_LABEL}
SPLITS = ("train", "validation", "test")


@dataclass(frozen=True)
class PromptInjectionDatasetSummary:
    output_path: Path
    summary_path: Path
    llmail_dir: Path
    clean_corpus_dir: Path
    row_count: int
    by_label: dict[str, int]
    by_source: dict[str, int]
    by_split: dict[str, int]
    max_text_chars: int
    seed: int
    warnings: list[str]


def _stable_split(stable_id: str, seed: int) -> str:
    digest = hashlib.sha256(f"{seed}:{stable_id}".encode("utf-8")).digest()
    bucket = int.from_bytes(digest[:4], "big") % 100
    if bucket < 80:
        return "train"
    if bucket < 90:
        return "validation"
    return "test"


def _truncate_text(text: str, max_chars: int) -> str:
    collapsed = re.sub(r"\s+", " ", text).strip()
    if max_chars <= 0 or len(collapsed) <= max_chars:
        return collapsed
    return collapsed[:max_chars].rstrip()


def _safe_header_value(message: Message, header: str) -> str:
    try:
        value = message.get(header)
        if value:
            return str(value)
    except Exception:
        pass
    try:
        values = [
            str(value)
            for key, value in message.raw_items()
            if key.lower() == header.lower()
        ]
    except Exception:
        values = []
    return ", ".join(values)


def _email_text_for_ml(sample_path: Path, max_text_chars: int) -> str:
    message = BytesParser(policy=policy.default).parsebytes(sample_path.read_bytes())
    sections: list[str] = []
    for header in ("Subject", "From", "Reply-To", "To"):
        value = _safe_header_value(message, header)
        if value:
            sections.append(f"{header}: {value}")

    body_chunks: list[str] = []
    for part in message.walk():
        if part.is_multipart() or part.get_content_maintype() != "text":
            continue
        try:
            body_chunks.append(str(part.get_content()))
        except LookupError:
            payload = part.get_payload(decode=True) or b""
            body_chunks.append(payload.decode("utf-8", errors="replace"))

    body = "\n".join(chunk.strip() for chunk in body_chunks if chunk.strip())
    if body:
        sections.append(f"Body:\n{body}")
    return _truncate_text("\n\n".join(sections), max_text_chars)


def _llmail_attack_rows(llmail_dir: Path, max_text_chars: int) -> Iterator[dict]:
    for filename in ("raw_submissions_phase1.jsonl", "raw_submissions_phase2.jsonl"):
        path = llmail_dir / filename
        if not path.exists():
            continue
        with path.open("r", encoding="utf-8") as fh:
            for index, line in enumerate(fh):
                if not line.strip():
                    continue
                row = json.loads(line)
                subject = str(row.get("subject") or "")
                body = str(row.get("body") or "")
                text = _truncate_text(
                    f"Subject: {subject}\n\nBody:\n{body}",
                    max_text_chars,
                )
                stable_id = f"{filename}:{row.get('RowKey') or index}"
                yield {
                    "id": stable_id,
                    "text": text,
                    "label": ATTACK_LABEL,
                    "source": "llmail_attack",
                    "source_path": f"{filename}#{index}",
                    "split": "",
                }


def _llmail_benign_rows(llmail_dir: Path, max_text_chars: int) -> Iterator[dict]:
    path = llmail_dir / "emails_for_fp_tests.json"
    if not path.exists():
        return
    data = json.loads(path.read_text(encoding="utf-8"))
    for index, value in enumerate(data):
        text = _truncate_text(str(value), max_text_chars)
        yield {
            "id": f"emails_for_fp_tests.json:{index}",
            "text": text,
            "label": CLEAN_LABEL,
            "source": "llmail_benign_fp",
            "source_path": f"emails_for_fp_tests.json#{index}",
            "split": "",
        }


def _clean_corpus_rows(clean_corpus_dir: Path, max_text_chars: int) -> Iterator[dict]:
    labels_csv = clean_corpus_dir / "labels.csv"
    if not labels_csv.exists():
        return
    with labels_csv.open("r", encoding="utf-8", newline="") as fh:
        for row in csv.DictReader(fh):
            if row.get("label") != CLEAN_LABEL:
                continue
            filename = row.get("filename", "")
            sample_path = clean_corpus_dir / filename
            if not filename or not sample_path.exists():
                continue
            text = _email_text_for_ml(sample_path, max_text_chars)
            yield {
                "id": f"clean_corpus:{filename}",
                "text": text,
                "label": CLEAN_LABEL,
                "source": row.get("source_corpus") or "clean_corpus",
                "source_path": row.get("source_path") or filename,
                "split": "",
            }


def _limited_rows(rows: Iterator[dict], limit: Optional[int], seed: int, source_name: str) -> Iterator[dict]:
    if limit is None or limit <= 0:
        return rows
    rng = random.Random(f"{seed}:{source_name}")
    sample: list[dict] = []
    seen = 0
    for row in rows:
        seen += 1
        if len(sample) < limit:
            sample.append(row)
            continue
        replace_at = rng.randrange(seen)
        if replace_at < limit:
            sample[replace_at] = row
    return iter(sample)


def prepare_prompt_injection_dataset(
    *,
    llmail_dir: Path = DEFAULT_LLMMAIL_DIR,
    clean_corpus_dir: Path = DEFAULT_CLEAN_CORPUS_DIR,
    output_path: Path = DEFAULT_OUTPUT_JSONL,
    max_text_chars: int = 12000,
    seed: int = 1337,
    max_attack: Optional[int] = None,
    max_clean: Optional[int] = None,
) -> PromptInjectionDatasetSummary:
    """Write a JSONL dataset for prompt-injection ML training."""

    llmail_dir = Path(llmail_dir)
    clean_corpus_dir = Path(clean_corpus_dir)
    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    warnings: list[str] = []

    if not llmail_dir.exists():
        raise FileNotFoundError(f"LLMail directory not found: {llmail_dir}")
    if not clean_corpus_dir.exists():
        raise FileNotFoundError(f"clean corpus directory not found: {clean_corpus_dir}")

    attack_rows = _limited_rows(
        _llmail_attack_rows(llmail_dir, max_text_chars),
        max_attack,
        seed,
        "llmail_attack",
    )
    clean_rows = _limited_rows(
        _clean_corpus_rows(clean_corpus_dir, max_text_chars),
        max_clean,
        seed,
        "clean_corpus",
    )
    llmail_clean_rows = _llmail_benign_rows(llmail_dir, max_text_chars)

    by_label: Counter[str] = Counter()
    by_source: Counter[str] = Counter()
    by_split: Counter[str] = Counter()
    row_count = 0

    with output_path.open("w", encoding="utf-8", newline="\n") as fh:
        for row in itertools.chain(attack_rows, clean_rows, llmail_clean_rows):
            row = dict(row)
            row["split"] = _stable_split(row["id"], seed)
            if row["label"] not in ALLOWED_LABELS:
                raise ValueError(f"invalid label: {row['label']}")
            by_label[row["label"]] += 1
            by_source[row["source"]] += 1
            by_split[row["split"]] += 1
            row_count += 1
            fh.write(json.dumps(row, sort_keys=True) + "\n")

    if by_source.get("llmail_attack", 0) == 0:
        warnings.append("no LLMail attack rows were written")
    if sum(
        count
        for source, count in by_source.items()
        if source in {"enron_ham", "spamassassin_ham"}
    ) == 0:
        warnings.append("no Enron/SpamAssassin clean rows were written")
    if by_source.get("llmail_benign_fp", 0) == 0:
        warnings.append("no LLMail benign false-positive rows were written")

    summary_path = output_path.with_suffix(".summary.json")
    summary = PromptInjectionDatasetSummary(
        output_path=output_path,
        summary_path=summary_path,
        llmail_dir=llmail_dir,
        clean_corpus_dir=clean_corpus_dir,
        row_count=row_count,
        by_label=dict(sorted(by_label.items())),
        by_source=dict(sorted(by_source.items())),
        by_split=dict(sorted(by_split.items())),
        max_text_chars=max_text_chars,
        seed=seed,
        warnings=warnings,
    )
    payload = asdict(summary)
    payload["output_path"] = str(summary.output_path)
    payload["summary_path"] = str(summary.summary_path)
    payload["llmail_dir"] = str(summary.llmail_dir)
    payload["clean_corpus_dir"] = str(summary.clean_corpus_dir)
    summary_path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return summary


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Prepare a shared prompt-injection ML JSONL dataset.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument("--llmail-dir", type=Path, default=DEFAULT_LLMMAIL_DIR)
    parser.add_argument("--clean-corpus-dir", type=Path, default=DEFAULT_CLEAN_CORPUS_DIR)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT_JSONL)
    parser.add_argument("--max-text-chars", type=int, default=12000)
    parser.add_argument("--seed", type=int, default=1337)
    parser.add_argument("--max-attack", type=int, default=0, help="Optional attack downsample cap; 0 means all")
    parser.add_argument("--max-clean", type=int, default=0, help="Optional clean downsample cap; 0 means all")
    return parser


def main(argv: Optional[list[str]] = None) -> int:
    parser = build_arg_parser()
    args = parser.parse_args(argv)
    summary = prepare_prompt_injection_dataset(
        llmail_dir=args.llmail_dir,
        clean_corpus_dir=args.clean_corpus_dir,
        output_path=args.output,
        max_text_chars=args.max_text_chars,
        seed=args.seed,
        max_attack=(args.max_attack or None),
        max_clean=(args.max_clean or None),
    )
    print(f"Wrote {summary.row_count} rows to {summary.output_path}")
    print("Labels:")
    for label, count in sorted(summary.by_label.items()):
        print(f"  {label}: {count}")
    print("Sources:")
    for source, count in sorted(summary.by_source.items()):
        print(f"  {source}: {count}")
    if summary.warnings:
        print("Warnings:")
        for warning in summary.warnings:
            print(f"  - {warning}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
