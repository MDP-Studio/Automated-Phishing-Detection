from pathlib import Path

from scripts import sigma_convert_check


def _write_sigma(path: Path) -> Path:
    path.write_text(
        "\n".join(
            [
                "title: Unit Test Rule",
                "id: 8edbcaa8-29a5-4fb3-8f07-76bffde99261",
                "status: test",
                "logsource:",
                "  category: email",
                "detection:",
                "  selection:",
                "    subject|contains: invoice",
                "  condition: selection",
                "level: low",
                "",
            ]
        ),
        encoding="utf-8",
    )
    return path


def test_sigma_conversion_check_records_success_with_converter(monkeypatch, tmp_path):
    rule = _write_sigma(tmp_path / "rule.yml")
    monkeypatch.setattr(sigma_convert_check, "_load_backend", lambda name: object())
    monkeypatch.setattr(sigma_convert_check, "_convert_rule", lambda path, backend: ["query"])

    check = sigma_convert_check.run_sigma_conversion_check([rule], require_converter=True)

    assert check.success
    assert check.status == "success"
    assert check.rules_checked == 1
    assert check.rules_converted == 1
    assert check.query_count == 1


def test_sigma_conversion_check_writes_safe_failure_status(monkeypatch, tmp_path):
    rule = tmp_path / "bad.yml"
    rule.write_text("title: bad\n", encoding="utf-8")
    monkeypatch.setattr(sigma_convert_check, "_load_backend", lambda name: object())

    check = sigma_convert_check.run_sigma_conversion_check([rule], require_converter=True)
    output = sigma_convert_check.write_sigma_conversion_status(check, tmp_path / "status.json")

    text = output.read_text(encoding="utf-8")
    assert not check.success
    assert '"status": "failed"' in text
    assert "bad.yml" in text
