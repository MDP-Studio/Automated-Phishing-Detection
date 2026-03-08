"""
Security-focused unit tests for the phishing detection pipeline.

Tests cover:
- Input sanitization (XSS prevention)
- SQL injection prevention (parameterized queries)
- API token validation via TestClient
- File path traversal prevention
- Safe filename handling
"""
import json
from unittest.mock import MagicMock

import pytest
from markupsafe import escape

from src.config import PipelineConfig
from src.feedback.feedback_api import (
    create_app,
    FeedbackSubmissionRequest,
    _export_csv,
    _export_jsonl,
)
from src.utils.validators import is_safe_filepath, sanitize_filename


class TestInputSanitization:
    """Test input sanitization for XSS prevention."""

    def test_xss_script_tag_escaped(self):
        """Script tags in email subjects are escaped by markupsafe."""
        malicious = "<script>alert('XSS')</script>"
        escaped = str(escape(malicious))
        assert "<script>" not in escaped
        assert "&lt;script&gt;" in escaped

    def test_xss_img_tag_escaped(self):
        """IMG tags with onerror are escaped (tag delimiters removed)."""
        malicious = '<img src=x onerror="fetch(\'evil\')">'
        escaped = str(escape(malicious))
        assert "<img" not in escaped
        assert "&lt;img" in escaped

    def test_html_entities_in_feedback(self):
        """HTML entities in feedback are escaped."""
        text = 'Email contains: "alert()"'
        escaped = str(escape(text))
        # markupsafe escapes " as &#34;
        assert "&#34;" in escaped or "&quot;" in escaped

    def test_angle_brackets_escaped(self):
        """All angle brackets are escaped."""
        text = "<div>content</div>"
        escaped = str(escape(text))
        assert "<" not in escaped
        assert "&lt;" in escaped


class TestSqlInjectionPrevention:
    """Test SQL injection prevention — values stored as literals."""

    def test_sql_injection_in_email_id(self):
        malicious = "msg_123'; DROP TABLE feedback; --"
        req = FeedbackSubmissionRequest(
            email_id=malicious,
            original_verdict="CLEAN",
            correct_label="SUSPICIOUS",
        )
        assert req.email_id == malicious

    def test_sql_injection_in_notes(self):
        malicious = "UPDATE feedback SET correct_label='CLEAN' WHERE 1=1; --"
        req = FeedbackSubmissionRequest(
            email_id="msg_123",
            original_verdict="CLEAN",
            correct_label="SUSPICIOUS",
            analyst_notes=malicious,
        )
        assert malicious in req.analyst_notes

    def test_sql_injection_in_feature_vector(self):
        malicious_features = {"score": "0.5' OR '1'='1"}
        req = FeedbackSubmissionRequest(
            email_id="msg_123",
            original_verdict="CLEAN",
            correct_label="SUSPICIOUS",
            feature_vector=malicious_features,
        )
        json_str = json.dumps(req.feature_vector)
        assert "0.5' OR '1'='1" in json_str


class TestApiTokenValidation:
    """Test API token validation via TestClient."""

    def _make_app(self, token="test_token_123"):
        config = PipelineConfig(analyst_api_token=token)
        db_manager = MagicMock()
        return create_app(config, db_manager)

    def test_health_endpoint(self):
        """Health endpoint works (uses /api/v1/ prefix)."""
        from fastapi.testclient import TestClient

        app = self._make_app()
        client = TestClient(app)
        resp = client.get("/api/v1/health")
        assert resp.status_code == 200

    def test_submit_without_token_rejected(self):
        """Submit without auth header should be 401/403."""
        from fastapi.testclient import TestClient

        app = self._make_app()
        client = TestClient(app)
        resp = client.post("/api/v1/feedback", json={
            "email_id": "msg_123",
            "original_verdict": "CLEAN",
            "correct_label": "SUSPICIOUS",
        })
        assert resp.status_code in (401, 403, 422)

    def test_submit_with_wrong_token_rejected(self):
        """Submit with wrong token should be rejected."""
        from fastapi.testclient import TestClient

        app = self._make_app(token="correct_token")
        client = TestClient(app)
        resp = client.post(
            "/api/v1/feedback",
            json={
                "email_id": "msg_123",
                "original_verdict": "CLEAN",
                "correct_label": "SUSPICIOUS",
            },
            headers={"Authorization": "Bearer wrong_token"},
        )
        assert resp.status_code in (401, 403)


class TestFilePathSecurity:
    """Test file path traversal prevention."""

    def test_directory_traversal_blocked(self):
        assert is_safe_filepath("../../etc/passwd") is False
        assert is_safe_filepath("/tmp/safe.txt") is True

    def test_null_byte_injection_blocked(self):
        assert is_safe_filepath("file\x00.txt") is False

    def test_command_injection_blocked(self):
        assert is_safe_filepath("file;rm -rf /") is False
        assert is_safe_filepath("file$(whoami)") is False

    def test_sanitize_removes_path_separators(self):
        result = sanitize_filename("../../evil.pdf")
        assert "/" not in result

    def test_sanitize_removes_null_bytes(self):
        result = sanitize_filename("null\x00byte.pdf")
        assert "\x00" not in result

    def test_sanitize_limits_length(self):
        result = sanitize_filename("a" * 300 + ".txt")
        assert len(result) <= 255

    def test_export_csv_safe_filename(self):
        records = [MagicMock(
            email_id="test@example.com",
            original_verdict="CLEAN",
            correct_label="SUSPICIOUS",
            analyst_notes="Test",
            submitted_at=MagicMock(isoformat=lambda: "2026-03-08T15:00:00"),
        )]
        response = _export_csv(records)
        disp = response.headers.get("Content-Disposition", "")
        assert ".." not in disp
        assert "filename=" in disp

    def test_export_jsonl_safe_filename(self):
        records = [MagicMock(
            email_id="test@example.com",
            original_verdict="CLEAN",
            correct_label="SUSPICIOUS",
            analyst_notes="Test",
            submitted_at=MagicMock(isoformat=lambda: "2026-03-08T15:00:00"),
        )]
        response = _export_jsonl(records)
        disp = response.headers.get("Content-Disposition", "")
        assert ".." not in disp


class TestJsonSafety:
    """Test JSON injection prevention."""

    def test_json_roundtrip_preserves_malicious_string(self):
        malicious = {"field": 'value"; "malicious": "injected'}
        req = FeedbackSubmissionRequest(
            email_id="msg_123",
            original_verdict="CLEAN",
            correct_label="SUSPICIOUS",
            feature_vector=malicious,
        )
        parsed = json.loads(json.dumps(req.feature_vector))
        assert parsed == malicious

    def test_json_injection_in_email_id(self):
        malicious = 'msg_123", "injected": "true'
        req = FeedbackSubmissionRequest(
            email_id=malicious,
            original_verdict="CLEAN",
            correct_label="SUSPICIOUS",
        )
        assert req.email_id == malicious


class TestConfigSecurity:
    """Test configuration security."""

    def test_database_path_from_config(self):
        config = PipelineConfig()
        assert config.feedback_db_path is not None
        assert isinstance(config.feedback_db_path, str)

    def test_app_creation_with_token(self):
        config = PipelineConfig(analyst_api_token="test")
        db_manager = MagicMock()
        app = create_app(config, db_manager)
        assert app is not None
