import re
from pathlib import Path

import yaml


ROOT = Path(__file__).resolve().parents[2]


def _locked_playwright_version() -> str:
    lock_text = (ROOT / "requirements.lock").read_text(encoding="utf-8")
    match = re.search(
        r"^playwright==([0-9]+\.[0-9]+\.[0-9]+)\b",
        lock_text,
        re.MULTILINE,
    )
    assert match, "requirements.lock must pin playwright"
    return match.group(1)


def test_browser_sandbox_server_matches_python_client() -> None:
    version = _locked_playwright_version()

    compose_files = (
        "docker-compose.yml",
        "docker-compose.production.yml",
    )
    for compose_file in compose_files:
        compose_text = (ROOT / compose_file).read_text(encoding="utf-8")
        compose = yaml.safe_load(compose_text)
        browser_sandbox = compose["services"]["browser-sandbox"]

        assert browser_sandbox["image"] == (
            f"mcr.microsoft.com/playwright:v{version}-noble"
        )
        assert browser_sandbox["command"][:3] == [
            "npx",
            "-y",
            f"playwright@{version}",
        ]
        assert browser_sandbox["command"][3] == "run-server"
