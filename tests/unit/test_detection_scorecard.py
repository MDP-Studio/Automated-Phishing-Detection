import json

from scripts import detection_scorecard


def _write_eval_run(tmp_path, run_id, *, recall):
    summary = {
        "run_id": run_id,
        "commit_sha": "abc123",
        "corpus_dir": "tests/real_world_samples",
        "sample_count": 2,
        "permissive": {
            "true_positive": 1,
            "false_positive": 0,
            "true_negative": 1,
            "false_negative": 0,
            "errors": 0,
            "precision": 1.0,
            "recall": recall,
            "f1": recall,
            "accuracy": 1.0,
        },
        "strict": {
            "true_positive": 1,
            "false_positive": 0,
            "true_negative": 1,
            "false_negative": 0,
            "errors": 0,
            "precision": 1.0,
            "recall": recall,
            "f1": recall,
            "accuracy": 1.0,
        },
    }
    summary_path = tmp_path / f"{run_id}.summary.json"
    summary_path.write_text(json.dumps(summary), encoding="utf-8")
    jsonl_path = tmp_path / f"{run_id}.jsonl"
    jsonl_path.write_text(
        "\n".join([
            json.dumps({"true_label": "PHISHING", "channel": "email"}),
            json.dumps({"true_label": "CLEAN", "channel": "sms"}),
        ])
        + "\n",
        encoding="utf-8",
    )
    return summary_path


def test_detection_scorecard_records_metrics_mix_and_delta(tmp_path):
    previous = _write_eval_run(tmp_path, "previous", recall=0.5)
    current = _write_eval_run(tmp_path, "current", recall=0.75)

    scorecard = detection_scorecard.build_scorecard(
        summary_path=current,
        previous_summary_path=previous,
    )

    assert scorecard["schema_version"] == "detection-scorecard.v1"
    assert scorecard["corpus_mix"]["labels"] == {"CLEAN": 1, "PHISHING": 1}
    assert scorecard["corpus_mix"]["channels"] == {"email": 1, "sms": 1}
    assert scorecard["delta_from_previous"]["permissive"]["recall"] == 0.25
    assert scorecard["privacy"]["contains_raw_message_body"] is False


def test_detection_scorecard_writes_json_and_markdown(tmp_path):
    current = _write_eval_run(tmp_path, "current", recall=1.0)

    scorecard = detection_scorecard.build_scorecard(summary_path=current)
    json_path, md_path = detection_scorecard.write_scorecard(scorecard, tmp_path / "reports")

    assert json_path.exists()
    assert md_path.exists()
    assert "raw bodies" in md_path.read_text(encoding="utf-8")
