import json

from scripts import validate_cti_freshness


def test_cti_freshness_rejects_stale_attack_mapping_doc(tmp_path, monkeypatch):
    docs = tmp_path / "docs"
    docs.mkdir()
    (docs / "MITRE_ATTACK_MAPPING.md").write_text("ATT&CK references are v14. T1566.001\n", encoding="utf-8")
    monkeypatch.setattr(
        validate_cti_freshness,
        "_load_analyzer_attack_tags",
        lambda: {"header_analysis": ["attack.t1566.001"]},
    )

    status = validate_cti_freshness.validate_cti_freshness(project_root=tmp_path)

    assert status["status"] == "failed"
    assert "v19.1" in status["failures"][0]


def test_cti_freshness_accepts_current_mapping_and_report(tmp_path, monkeypatch):
    docs = tmp_path / "docs"
    docs.mkdir()
    (docs / "MITRE_ATTACK_MAPPING.md").write_text("ATT&CK Enterprise v19.1 covers T1566.001\n", encoding="utf-8")
    report_path = tmp_path / "cti_report.json"
    report_path.write_text(json.dumps({"overall_status": "success"}), encoding="utf-8")
    monkeypatch.setattr(
        validate_cti_freshness,
        "_load_analyzer_attack_tags",
        lambda: {"header_analysis": ["attack.t1566.001"]},
    )
    monkeypatch.setattr(
        validate_cti_freshness,
        "_load_signed_compatibility_report",
        lambda path: {
            "overall_status": "success",
            "compatibility_targets": [
                {"name": "signed_export_manifest", "status": "success"},
                {"name": "opencti_taxii_ingest", "status": "success"},
                {"name": "sigma_splunk_conversion", "status": "success"},
            ],
        },
    )

    status = validate_cti_freshness.validate_cti_freshness(
        project_root=tmp_path,
        report_path=report_path,
    )

    assert status["status"] == "success"
    assert status["report_status"] == "success"
