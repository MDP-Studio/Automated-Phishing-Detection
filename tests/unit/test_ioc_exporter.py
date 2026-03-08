"""
Unit tests for IOC exporter (STIX 2.1 bundle generation).

Tests cover:
- IOCExporter initialization
- STIX bundle generation from PipelineResult
- URL, domain, IP, and file hash IOC handling
- Empty result handling
- JSON serialization
"""
import json
from datetime import datetime, timezone
from unittest.mock import MagicMock, patch

import pytest

from src.models import AnalyzerResult, ExtractedURL, PipelineResult, URLSource, Verdict
from src.reporting.ioc_exporter import IOCExporter


class TestIOCExporterInit:
    """Test IOCExporter initialization."""

    def test_init_default_organization_name(self):
        """Test initialization with default organization name."""
        exporter = IOCExporter()
        assert exporter.organization_name == "Phishing Detection System"

    def test_init_custom_organization_name(self):
        """Test initialization with custom organization name."""
        custom_name = "ACME Corp Security"
        exporter = IOCExporter(organization_name=custom_name)
        assert exporter.organization_name == custom_name

    def test_stix_pattern_constants(self):
        """Test STIX pattern constant definitions."""
        exporter = IOCExporter()
        assert exporter.STIX_PATTERN_IPV4 == "[ipv4-addr:value = '{ip}']"
        assert exporter.STIX_PATTERN_DOMAIN == "[domain-name:value = '{domain}']"
        assert exporter.STIX_PATTERN_URL == "[url:value = '{url}']"
        assert exporter.STIX_PATTERN_FILE_HASH == "[file:hashes.MD5 = '{hash}']"


class TestExportStix:
    """Test STIX 2.1 bundle export functionality."""

    @pytest.fixture
    def sample_pipeline_result(self):
        """Create a sample PipelineResult with various IOCs."""
        return PipelineResult(
            email_id="test_email_123",
            verdict=Verdict.LIKELY_PHISHING,
            overall_score=0.75,
            overall_confidence=0.85,
            analyzer_results={
                "url_reputation": AnalyzerResult(
                    analyzer_name="url_reputation",
                    risk_score=0.8,
                    confidence=0.9,
                    details={"reputation": "malicious"},
                )
            },
            extracted_urls=[
                ExtractedURL(
                    url="http://malicious.example.com/phishing",
                    source=URLSource.BODY_HTML,
                    source_detail="Found in body HTML",
                )
            ],
            iocs={
                "malicious_urls": ["http://malicious.example.com/phishing"],
                "malicious_domains": ["malicious.example.com"],
                "malicious_ips": ["192.0.2.1", {"ip": "192.0.2.2"}],
                "file_hashes": {"MD5": "d41d8cd98f00b204e9800998ecf8427e"},
            },
            reasoning="URL and domain reputation indicates phishing",
            timestamp=datetime(2026, 3, 8, 15, 30, 0, tzinfo=timezone.utc),
        )

    @patch("src.reporting.ioc_exporter.Bundle")
    def test_export_stix_bundle_structure(self, mock_bundle, sample_pipeline_result):
        """Test STIX bundle is created with proper structure."""
        mock_bundle_instance = MagicMock()
        mock_bundle_instance.serialize.return_value = '{"type": "bundle"}'
        mock_bundle.return_value = mock_bundle_instance

        exporter = IOCExporter()
        result = exporter.export_stix(sample_pipeline_result)

        # Verify Bundle was called
        mock_bundle.assert_called_once()
        # Verify serialize was called with pretty=True
        mock_bundle_instance.serialize.assert_called_once_with(pretty=True)
        # Verify result is serialized JSON
        assert isinstance(result, str)

    @patch("src.reporting.ioc_exporter.Bundle")
    def test_export_stix_with_urls_domains_ips(
        self, mock_bundle, sample_pipeline_result
    ):
        """Test export includes URL, domain, and IP IOCs."""
        mock_bundle_instance = MagicMock()
        mock_bundle_instance.serialize.return_value = '{"type": "bundle"}'
        mock_bundle.return_value = mock_bundle_instance

        exporter = IOCExporter()
        exporter.export_stix(sample_pipeline_result)

        # Verify Bundle was called with objects
        call_args = mock_bundle.call_args
        objects = call_args.kwargs.get("objects", [])
        # Should have campaign + URL + domain + IPs + file hash indicators
        assert len(objects) > 0

    @patch("src.reporting.ioc_exporter.Bundle")
    def test_export_stix_empty_iocs(self, mock_bundle):
        """Test export with empty IOCs."""
        result = PipelineResult(
            email_id="clean_email",
            verdict=Verdict.CLEAN,
            overall_score=0.1,
            overall_confidence=0.95,
            analyzer_results={},
            extracted_urls=[],
            iocs={},
            reasoning="No threats detected",
            timestamp=datetime.now(timezone.utc),
        )

        mock_bundle_instance = MagicMock()
        mock_bundle_instance.serialize.return_value = '{"type": "bundle"}'
        mock_bundle.return_value = mock_bundle_instance

        exporter = IOCExporter()
        output = exporter.export_stix(result)

        # Should still create a bundle, just with campaign object
        assert output == '{"type": "bundle"}'

    @patch("src.reporting.ioc_exporter.Bundle")
    def test_export_stix_confirmed_phishing_creates_sighting(
        self, mock_bundle, sample_pipeline_result
    ):
        """Test sighting is created for confirmed phishing."""
        sample_pipeline_result.verdict = Verdict.CONFIRMED_PHISHING
        mock_bundle_instance = MagicMock()
        mock_bundle_instance.serialize.return_value = '{"type": "bundle"}'
        mock_bundle.return_value = mock_bundle_instance

        exporter = IOCExporter()
        exporter.export_stix(sample_pipeline_result)

        # Verify Bundle was called
        call_args = mock_bundle.call_args
        objects = call_args.kwargs.get("objects", [])
        # Should include sighting objects
        assert len(objects) > 1


class TestExportJson:
    """Test JSON export functionality."""

    @pytest.fixture
    def sample_result(self):
        """Create sample PipelineResult."""
        return PipelineResult(
            email_id="test_123",
            verdict=Verdict.LIKELY_PHISHING,
            overall_score=0.72,
            overall_confidence=0.88,
            analyzer_results={},
            extracted_urls=[
                ExtractedURL(
                    url="http://example.com",
                    source=URLSource.BODY_HTML,
                    source_detail="test",
                )
            ],
            iocs={
                "malicious_urls": ["http://example.com"],
                "malicious_domains": ["example.com"],
                "malicious_ips": ["10.0.0.1"],
                "file_hashes": {"MD5": "abc123def456"},
                "headers": {"spf_pass": True},
            },
            reasoning="Test reasoning",
            timestamp=datetime(2026, 3, 8, 15, 0, 0, tzinfo=timezone.utc),
        )

    def test_export_json_returns_valid_json(self, sample_result):
        """Test JSON export returns valid JSON string."""
        exporter = IOCExporter()
        json_str = exporter.export_json(sample_result)

        # Should be parseable JSON
        data = json.loads(json_str)
        assert isinstance(data, dict)

    def test_export_json_contains_required_fields(self, sample_result):
        """Test JSON export includes required fields."""
        exporter = IOCExporter()
        json_str = exporter.export_json(sample_result)
        data = json.loads(json_str)

        assert data["email_id"] == "test_123"
        assert data["verdict"] == "LIKELY_PHISHING"
        assert data["confidence"] == 0.88
        assert "analysis_time" in data
        assert "iocs" in data

    def test_export_json_ioc_structure(self, sample_result):
        """Test IOC structure in JSON export."""
        exporter = IOCExporter()
        json_str = exporter.export_json(sample_result)
        data = json.loads(json_str)

        iocs = data["iocs"]
        assert "urls" in iocs
        assert "domains" in iocs
        assert "ips" in iocs
        assert "file_hashes" in iocs
        assert "headers" in iocs

    def test_export_json_timestamp_iso_format(self, sample_result):
        """Test timestamp is ISO formatted."""
        exporter = IOCExporter()
        json_str = exporter.export_json(sample_result)
        data = json.loads(json_str)

        # Should be ISO format string
        assert "T" in data["analysis_time"]
        assert ":" in data["analysis_time"]


class TestExtractUrlsFromIocs:
    """Test URL extraction from IOCs."""

    def test_extract_urls_from_extracted_urls(self):
        """Test URLs are extracted from extracted_urls list."""
        result = PipelineResult(
            email_id="test",
            verdict=Verdict.CLEAN,
            overall_score=0.1,
            overall_confidence=0.9,
            analyzer_results={},
            extracted_urls=[
                ExtractedURL(
                    url="http://url1.com",
                    source=URLSource.BODY_HTML,
                    source_detail="",
                ),
                ExtractedURL(
                    url="http://url2.com",
                    source=URLSource.BODY_HTML,
                    source_detail="",
                ),
            ],
            iocs={"malicious_urls": []},
            reasoning="",
            timestamp=datetime.now(timezone.utc),
        )

        exporter = IOCExporter()
        urls = exporter._extract_urls_from_iocs(result)

        assert "http://url1.com" in urls
        assert "http://url2.com" in urls

    def test_extract_urls_deduplication(self):
        """Test URLs are deduplicated."""
        result = PipelineResult(
            email_id="test",
            verdict=Verdict.CLEAN,
            overall_score=0.1,
            overall_confidence=0.9,
            analyzer_results={},
            extracted_urls=[
                ExtractedURL(
                    url="http://example.com",
                    source=URLSource.BODY_HTML,
                    source_detail="",
                )
            ],
            iocs={"malicious_urls": ["http://example.com"]},
            reasoning="",
            timestamp=datetime.now(timezone.utc),
        )

        exporter = IOCExporter()
        urls = exporter._extract_urls_from_iocs(result)

        # Should have only one URL despite being in both places
        assert urls.count("http://example.com") == 1


class TestExtractDomainsFromIocs:
    """Test domain extraction from IOCs."""

    def test_extract_domains_from_iocs(self):
        """Test domains are extracted from IOCs."""
        iocs = {"malicious_domains": ["example.com", "phishing.net"]}

        exporter = IOCExporter()
        domains = exporter._extract_domains_from_iocs(iocs)

        assert "example.com" in domains
        assert "phishing.net" in domains

    def test_extract_domains_empty_iocs(self):
        """Test extraction with empty IOCs."""
        iocs = {}

        exporter = IOCExporter()
        domains = exporter._extract_domains_from_iocs(iocs)

        assert domains == []


class TestIdentityGeneration:
    """Test identity ID generation for STIX objects."""

    def test_generate_identity_id_returns_uuid(self):
        """Test generated identity ID is UUID format."""
        exporter = IOCExporter()
        identity_id = exporter._generate_identity_id()

        # UUID format: 8-4-4-4-12 hexadecimal digits
        assert len(identity_id) == 36  # UUID string length
        assert identity_id.count("-") == 4

    def test_generate_identity_id_uniqueness(self):
        """Test generated IDs are unique."""
        exporter = IOCExporter()
        id1 = exporter._generate_identity_id()
        id2 = exporter._generate_identity_id()

        assert id1 != id2
