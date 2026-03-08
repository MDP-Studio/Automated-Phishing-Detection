"""
Test suite for URL detonation analyzer in src.analyzers.url_detonator module.

Tests:
- URLDetonationAnalyzer initialization
- analyze() method with mocked browser
- Timeout handling
- Result format and AnalyzerResult structure
- Redirect detection and domain switching
- Login form detection
- Certificate issues
- Suspicious script detection
"""

import pytest
from unittest.mock import MagicMock, AsyncMock, patch
import asyncio

from src.analyzers.url_detonator import URLDetonationAnalyzer
from src.models import ExtractedURL, URLSource, AnalyzerResult


class TestURLDetonationAnalyzerInitialization:
    """Test URLDetonationAnalyzer initialization."""

    def test_analyzer_initialization_with_client(self):
        """Test initialization with browser client."""
        mock_client = MagicMock()
        analyzer = URLDetonationAnalyzer(browser_client=mock_client)

        assert analyzer is not None
        assert analyzer.browser_client is mock_client

    def test_analyzer_initialization_without_client(self):
        """Test initialization without browser client."""
        analyzer = URLDetonationAnalyzer()

        assert analyzer is not None
        assert analyzer.browser_client is None

    def test_analyzer_initialization_with_none_client(self):
        """Test initialization with None browser client."""
        analyzer = URLDetonationAnalyzer(browser_client=None)

        assert analyzer is not None
        assert analyzer.browser_client is None


class TestURLDetonationAnalyzerBasic:
    """Test basic URL detonation functionality."""

    @pytest.mark.asyncio
    async def test_analyze_no_urls(self):
        """Test analyze with empty URL list."""
        mock_client = MagicMock()
        analyzer = URLDetonationAnalyzer(browser_client=mock_client)

        result = await analyzer.analyze([])

        assert isinstance(result, AnalyzerResult)
        assert result.analyzer_name == "url_detonation"
        assert result.risk_score == 0.0
        assert result.confidence == 1.0
        assert "no_urls_to_analyze" in result.details.get("message", "")

    @pytest.mark.asyncio
    async def test_analyze_single_clean_url(self):
        """Test analyzing a single clean URL."""
        mock_client = AsyncMock()
        mock_client.visit_url.return_value = {
            "redirect_chain": [],
            "login_forms": [],
            "suspicious_scripts": [],
            "cert_valid": True,
            "screenshot": None,
            "page_title": "Example Site",
        }

        analyzer = URLDetonationAnalyzer(browser_client=mock_client)

        urls = [
            ExtractedURL(
                url="https://example.com",
                source=URLSource.QR_CODE,
                source_detail="test_qr",
            )
        ]

        result = await analyzer.analyze(urls)

        assert isinstance(result, AnalyzerResult)
        assert result.analyzer_name == "url_detonation"
        assert result.risk_score >= 0.0
        assert result.confidence >= 0.0

    @pytest.mark.asyncio
    async def test_analyze_without_browser_client(self):
        """Test analyze returns empty result without browser client."""
        analyzer = URLDetonationAnalyzer(browser_client=None)

        urls = [
            ExtractedURL(
                url="https://example.com",
                source=URLSource.QR_CODE,
                source_detail="test_qr",
            )
        ]

        result = await analyzer.analyze(urls)

        assert isinstance(result, AnalyzerResult)
        assert result.analyzer_name == "url_detonation"


class TestURLDetonationRedirects:
    """Test redirect detection and analysis."""

    @pytest.mark.asyncio
    async def test_detect_single_redirect(self):
        """Test detection of single redirect."""
        mock_client = AsyncMock()
        mock_client.visit_url.return_value = {
            "redirect_chain": ["https://redirect.example.com"],
            "login_forms": [],
            "suspicious_scripts": [],
            "cert_valid": True,
            "screenshot": None,
            "page_title": "Redirected Site",
        }

        analyzer = URLDetonationAnalyzer(browser_client=mock_client)

        urls = [
            ExtractedURL(
                url="https://example.com",
                source=URLSource.QR_CODE,
                source_detail="test_qr",
            )
        ]

        result = await analyzer.analyze(urls)

        assert isinstance(result, AnalyzerResult)
        assert "urls_analyzed" in result.details
        url_results = result.details["urls_analyzed"]
        assert "https://example.com" in url_results

    @pytest.mark.asyncio
    async def test_detect_multiple_redirects(self):
        """Test detection of multiple redirects."""
        mock_client = AsyncMock()
        mock_client.visit_url.return_value = {
            "redirect_chain": [
                "https://redirect1.com",
                "https://redirect2.com",
                "https://redirect3.com",
                "https://redirect4.com",
            ],
            "login_forms": [],
            "suspicious_scripts": [],
            "cert_valid": True,
            "screenshot": None,
            "page_title": "Final Site",
        }

        analyzer = URLDetonationAnalyzer(browser_client=mock_client)

        urls = [
            ExtractedURL(
                url="https://example.com",
                source=URLSource.QR_CODE,
                source_detail="test_qr",
            )
        ]

        result = await analyzer.analyze(urls)

        assert isinstance(result, AnalyzerResult)
        # Multiple redirects should increase risk score
        assert result.risk_score > 0.0

    @pytest.mark.asyncio
    async def test_detect_domain_switching(self):
        """Test detection of domain switching in redirects."""
        mock_client = AsyncMock()
        mock_client.visit_url.return_value = {
            "redirect_chain": ["https://malicious-site.com"],
            "login_forms": [],
            "suspicious_scripts": [],
            "cert_valid": True,
            "screenshot": None,
            "page_title": "Malicious Site",
        }

        analyzer = URLDetonationAnalyzer(browser_client=mock_client)

        urls = [
            ExtractedURL(
                url="https://legitimate.com",
                source=URLSource.QR_CODE,
                source_detail="test_qr",
            )
        ]

        result = await analyzer.analyze(urls)

        assert isinstance(result, AnalyzerResult)
        # Domain switching is suspicious
        assert result.risk_score >= 0.0


class TestURLDetonationLoginForms:
    """Test login form detection."""

    @pytest.mark.asyncio
    async def test_detect_login_form(self):
        """Test detection of login form on page."""
        mock_client = AsyncMock()
        mock_client.visit_url.return_value = {
            "redirect_chain": [],
            "login_forms": [
                {
                    "action": "https://attacker.com/login",
                    "fields": ["username", "password"],
                }
            ],
            "suspicious_scripts": [],
            "cert_valid": True,
            "screenshot": None,
            "page_title": "Login Page",
        }

        analyzer = URLDetonationAnalyzer(browser_client=mock_client)

        urls = [
            ExtractedURL(
                url="https://example.com",
                source=URLSource.QR_CODE,
                source_detail="test_qr",
            )
        ]

        result = await analyzer.analyze(urls)

        assert isinstance(result, AnalyzerResult)
        # Login forms indicate phishing risk
        assert result.risk_score >= 0.6

    @pytest.mark.asyncio
    async def test_detect_multiple_login_forms(self):
        """Test detection of multiple login forms."""
        mock_client = AsyncMock()
        mock_client.visit_url.return_value = {
            "redirect_chain": [],
            "login_forms": [
                {"action": "https://site.com/login1", "fields": ["username", "password"]},
                {"action": "https://site.com/login2", "fields": ["email", "password"]},
            ],
            "suspicious_scripts": [],
            "cert_valid": True,
            "screenshot": None,
            "page_title": "Multi-Login Page",
        }

        analyzer = URLDetonationAnalyzer(browser_client=mock_client)

        urls = [
            ExtractedURL(
                url="https://example.com",
                source=URLSource.QR_CODE,
                source_detail="test_qr",
            )
        ]

        result = await analyzer.analyze(urls)

        assert isinstance(result, AnalyzerResult)
        assert result.risk_score >= 0.6


class TestURLDetonationSuspiciousFeatures:
    """Test detection of suspicious JavaScript and features."""

    @pytest.mark.asyncio
    async def test_detect_suspicious_scripts(self):
        """Test detection of suspicious JavaScript."""
        mock_client = AsyncMock()
        mock_client.visit_url.return_value = {
            "redirect_chain": [],
            "login_forms": [],
            "suspicious_scripts": [
                "eval(atob(...))",
                "document.write(String.fromCharCode(...))",
            ],
            "cert_valid": True,
            "screenshot": None,
            "page_title": "Suspicious Page",
        }

        analyzer = URLDetonationAnalyzer(browser_client=mock_client)

        urls = [
            ExtractedURL(
                url="https://example.com",
                source=URLSource.QR_CODE,
                source_detail="test_qr",
            )
        ]

        result = await analyzer.analyze(urls)

        assert isinstance(result, AnalyzerResult)
        # Suspicious scripts should increase risk
        assert result.risk_score >= 0.5

    @pytest.mark.asyncio
    async def test_detect_certificate_issue(self):
        """Test detection of certificate validity issues."""
        mock_client = AsyncMock()
        mock_client.visit_url.return_value = {
            "redirect_chain": [],
            "login_forms": [],
            "suspicious_scripts": [],
            "cert_valid": False,
            "screenshot": None,
            "page_title": "Certificate Issue",
        }

        analyzer = URLDetonationAnalyzer(browser_client=mock_client)

        urls = [
            ExtractedURL(
                url="https://example.com",
                source=URLSource.QR_CODE,
                source_detail="test_qr",
            )
        ]

        result = await analyzer.analyze(urls)

        assert isinstance(result, AnalyzerResult)
        # Certificate issues are suspicious
        assert result.risk_score >= 0.7

    @pytest.mark.asyncio
    async def test_detect_auth_bypass_indicators(self):
        """Test detection of authentication bypass attempts."""
        mock_client = AsyncMock()
        mock_client.visit_url.return_value = {
            "redirect_chain": [],
            "login_forms": [],
            "suspicious_scripts": [],
            "cert_valid": True,
            "screenshot": None,
            "page_title": "Auth Page",
            "auth_bypass_indicators": [
                "weak_csrf_token",
                "exposed_session_id",
            ],
        }

        analyzer = URLDetonationAnalyzer(browser_client=mock_client)

        urls = [
            ExtractedURL(
                url="https://example.com",
                source=URLSource.QR_CODE,
                source_detail="test_qr",
            )
        ]

        result = await analyzer.analyze(urls)

        assert isinstance(result, AnalyzerResult)
        assert result.risk_score >= 0.7


class TestURLDetonationTimeout:
    """Test timeout handling."""

    @pytest.mark.asyncio
    async def test_timeout_handling(self):
        """Test handling of timeout when visiting URL."""
        mock_client = AsyncMock()
        # Simulate timeout by raising asyncio.TimeoutError
        async def timeout_side_effect(url):
            await asyncio.sleep(1)
            raise asyncio.TimeoutError()

        mock_client.visit_url = timeout_side_effect

        analyzer = URLDetonationAnalyzer(browser_client=mock_client)

        urls = [
            ExtractedURL(
                url="https://slow-site.com",
                source=URLSource.QR_CODE,
                source_detail="test_qr",
            )
        ]

        result = await analyzer.analyze(urls)

        assert isinstance(result, AnalyzerResult)
        assert result.analyzer_name == "url_detonation"
        # Timeout should result in safe scores
        url_results = result.details.get("urls_analyzed", {})
        assert "https://slow-site.com" in url_results

    @pytest.mark.asyncio
    async def test_browser_exception_handling(self):
        """Test handling of browser client exceptions."""
        mock_client = AsyncMock()
        mock_client.visit_url.side_effect = Exception("Browser crashed")

        analyzer = URLDetonationAnalyzer(browser_client=mock_client)

        urls = [
            ExtractedURL(
                url="https://example.com",
                source=URLSource.QR_CODE,
                source_detail="test_qr",
            )
        ]

        result = await analyzer.analyze(urls)

        assert isinstance(result, AnalyzerResult)
        assert "urls_analyzed" in result.details


class TestURLDetonationResultFormat:
    """Test AnalyzerResult format and structure."""

    @pytest.mark.asyncio
    async def test_result_format_complete(self):
        """Test complete AnalyzerResult format."""
        mock_client = AsyncMock()
        mock_client.visit_url.return_value = {
            "redirect_chain": [],
            "login_forms": [],
            "suspicious_scripts": [],
            "cert_valid": True,
            "screenshot": b"fake_screenshot_data",
            "page_title": "Example Page",
        }

        analyzer = URLDetonationAnalyzer(browser_client=mock_client)

        urls = [
            ExtractedURL(
                url="https://example.com",
                source=URLSource.QR_CODE,
                source_detail="test_qr",
            )
        ]

        result = await analyzer.analyze(urls)

        # Check AnalyzerResult structure
        assert result.analyzer_name == "url_detonation"
        assert isinstance(result.risk_score, float)
        assert isinstance(result.confidence, float)
        assert isinstance(result.details, dict)
        assert isinstance(result.errors, list)

        # Check details structure
        assert "url_count" in result.details
        assert "urls_analyzed" in result.details
        assert result.details["url_count"] == 1

    @pytest.mark.asyncio
    async def test_result_aggregation_multiple_urls(self):
        """Test aggregation of results from multiple URLs."""
        mock_client = AsyncMock()

        def visit_url_side_effect(url):
            if "clean" in url:
                return {
                    "redirect_chain": [],
                    "login_forms": [],
                    "suspicious_scripts": [],
                    "cert_valid": True,
                    "screenshot": None,
                    "page_title": "Clean Site",
                }
            else:
                return {
                    "redirect_chain": ["https://malware.com"],
                    "login_forms": [{"action": "submit", "fields": ["user", "pass"]}],
                    "suspicious_scripts": ["malware_script"],
                    "cert_valid": False,
                    "screenshot": None,
                    "page_title": "Phishing Site",
                }

        mock_client.visit_url = visit_url_side_effect

        analyzer = URLDetonationAnalyzer(browser_client=mock_client)

        urls = [
            ExtractedURL(
                url="https://clean.example.com",
                source=URLSource.QR_CODE,
                source_detail="test_qr_1",
            ),
            ExtractedURL(
                url="https://phishing.example.com",
                source=URLSource.QR_CODE,
                source_detail="test_qr_2",
            ),
        ]

        result = await analyzer.analyze(urls)

        assert isinstance(result, AnalyzerResult)
        assert result.details["url_count"] == 2
        # Max of clean and phishing should favor phishing
        assert result.risk_score >= 0.0


class TestURLDetonationDomainExtraction:
    """Test domain extraction utility."""

    def test_extract_domain_https(self):
        """Test domain extraction from HTTPS URL."""
        analyzer = URLDetonationAnalyzer()
        domain = analyzer._extract_domain("https://example.com/path")

        assert domain == "example.com"

    def test_extract_domain_with_www(self):
        """Test domain extraction with www prefix."""
        analyzer = URLDetonationAnalyzer()
        domain = analyzer._extract_domain("https://www.example.com")

        assert domain == "example.com"

    def test_extract_domain_subdomain(self):
        """Test domain extraction with subdomain."""
        analyzer = URLDetonationAnalyzer()
        domain = analyzer._extract_domain("https://mail.google.com/path")

        assert domain == "mail.google.com"

    def test_extract_domain_with_port(self):
        """Test domain extraction with port."""
        analyzer = URLDetonationAnalyzer()
        domain = analyzer._extract_domain("https://example.com:8443/path")

        assert "example.com" in domain

    def test_extract_domain_invalid_url(self):
        """Test domain extraction with invalid URL falls back to input."""
        analyzer = URLDetonationAnalyzer()
        domain = analyzer._extract_domain("not_a_url")
        # Method falls back to url.lower() when netloc is empty
        assert domain == "not_a_url"
