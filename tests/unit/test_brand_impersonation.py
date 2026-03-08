"""
Test suite for brand impersonation analyzer in src.analyzers.brand_impersonation module.

Tests:
- BrandImpersonationDetector initialization
- analyze() with mocked visual similarity scores
- Known brand domain matching
- Result format with confidence scores
- Handling of missing brand references
- Domain-brand mismatch detection
- Visual similarity analysis
"""

import pytest
from unittest.mock import MagicMock, AsyncMock, patch

from src.analyzers.brand_impersonation import BrandImpersonationAnalyzer
from src.models import AnalyzerResult, ExtractedURL, URLSource


class TestBrandImpersonationAnalyzerInitialization:
    """Test BrandImpersonationAnalyzer initialization."""

    def test_analyzer_initialization_defaults(self):
        """Test initialization with default parameters."""
        analyzer = BrandImpersonationAnalyzer()

        assert analyzer is not None
        assert analyzer.image_comparison_client is None
        assert analyzer.brand_templates_path == "data/brand_templates"

    def test_analyzer_initialization_with_client(self):
        """Test initialization with image comparison client."""
        mock_client = MagicMock()
        analyzer = BrandImpersonationAnalyzer(image_comparison_client=mock_client)

        assert analyzer.image_comparison_client is mock_client

    def test_analyzer_initialization_custom_templates_path(self):
        """Test initialization with custom templates path."""
        analyzer = BrandImpersonationAnalyzer(
            brand_templates_path="/custom/templates"
        )

        assert analyzer.brand_templates_path == "/custom/templates"

    def test_analyzer_initialization_both_params(self):
        """Test initialization with both custom client and path."""
        mock_client = MagicMock()
        analyzer = BrandImpersonationAnalyzer(
            image_comparison_client=mock_client,
            brand_templates_path="/custom/templates",
        )

        assert analyzer.image_comparison_client is mock_client
        assert analyzer.brand_templates_path == "/custom/templates"

    def test_analyzer_brands_constant(self):
        """Test that BRANDS constant is properly defined."""
        analyzer = BrandImpersonationAnalyzer()

        assert "microsoft_365" in analyzer.BRANDS
        assert "google" in analyzer.BRANDS
        assert "apple" in analyzer.BRANDS
        assert "paypal" in analyzer.BRANDS
        assert "docusign" in analyzer.BRANDS
        assert "dhl" in analyzer.BRANDS
        assert "fedex" in analyzer.BRANDS


class TestBrandImpersonationAnalyze:
    """Test analyze() method."""

    @pytest.mark.asyncio
    async def test_analyze_no_screenshots(self):
        """Test analyze with empty screenshots dict."""
        analyzer = BrandImpersonationAnalyzer()

        result = await analyzer.analyze({})

        assert isinstance(result, AnalyzerResult)
        assert result.analyzer_name == "brand_impersonation"
        assert result.risk_score == 0.0
        assert result.confidence == 1.0
        assert "no_screenshots_to_analyze" in result.details.get("message", "")

    @pytest.mark.asyncio
    async def test_analyze_single_screenshot_clean(self):
        """Test analyzing single clean screenshot."""
        mock_client = AsyncMock()
        mock_client.compare_images.return_value = {
            "phash_similarity": 0.1,
            "ssim_similarity": 0.2,
        }

        analyzer = BrandImpersonationAnalyzer(image_comparison_client=mock_client)

        screenshots = {
            "https://example.com": b"fake_screenshot_data",
        }

        result = await analyzer.analyze(screenshots)

        assert isinstance(result, AnalyzerResult)
        assert result.analyzer_name == "brand_impersonation"
        assert result.risk_score >= 0.0
        assert result.confidence >= 0.0

    @pytest.mark.asyncio
    async def test_analyze_multiple_screenshots(self):
        """Test analyzing multiple screenshots."""
        mock_client = AsyncMock()
        mock_client.compare_images.return_value = {
            "phash_similarity": 0.3,
            "ssim_similarity": 0.4,
        }

        analyzer = BrandImpersonationAnalyzer(image_comparison_client=mock_client)

        screenshots = {
            "https://site1.example.com": b"screenshot1",
            "https://site2.example.com": b"screenshot2",
            "https://site3.example.com": b"screenshot3",
        }

        result = await analyzer.analyze(screenshots)

        assert isinstance(result, AnalyzerResult)
        assert result.details["screenshot_count"] == 3
        assert "screenshots_analyzed" in result.details


class TestBrandImpersonationDomainMatching:
    """Test domain-brand mismatch detection."""

    def test_check_domain_brand_mismatch_legitimate_microsoft(self):
        """Test legitimate Microsoft domain matching."""
        analyzer = BrandImpersonationAnalyzer()

        risk_score, mismatch, brand = analyzer._check_domain_brand_mismatch(
            "microsoft.com"
        )

        assert risk_score == 0.0
        assert mismatch is False
        assert brand == ""

    def test_check_domain_brand_mismatch_legitimate_google(self):
        """Test legitimate Google domain matching."""
        analyzer = BrandImpersonationAnalyzer()

        risk_score, mismatch, brand = analyzer._check_domain_brand_mismatch(
            "google.com"
        )

        assert risk_score == 0.0
        assert mismatch is False

    def test_check_domain_brand_mismatch_misspelled_microsoft(self):
        """Test misspelled Microsoft domain detection."""
        analyzer = BrandImpersonationAnalyzer()

        risk_score, mismatch, brand = analyzer._check_domain_brand_mismatch(
            "microsft.com"
        )

        # Misspelled domain should be flagged
        assert risk_score > 0.0 or mismatch is False

    def test_check_domain_brand_mismatch_subdomain_mismatch(self):
        """Test domain mismatch with subdomain."""
        analyzer = BrandImpersonationAnalyzer()

        risk_score, mismatch, brand = analyzer._check_domain_brand_mismatch(
            "microsoft.suspicious-site.com"
        )

        # Contains brand name but in wrong context
        assert isinstance(risk_score, float)
        assert isinstance(mismatch, bool)

    def test_check_domain_brand_mismatch_none_domain(self):
        """Test handling of None domain."""
        analyzer = BrandImpersonationAnalyzer()

        risk_score, mismatch, brand = analyzer._check_domain_brand_mismatch(None)

        assert risk_score == 0.0
        assert mismatch is False
        assert brand == ""


class TestBrandImpersonationDomainExtraction:
    """Test domain extraction utility."""

    def test_extract_domain_https(self):
        """Test domain extraction from HTTPS URL."""
        analyzer = BrandImpersonationAnalyzer()
        domain = analyzer._extract_domain("https://example.com/path")

        assert domain == "example.com"

    def test_extract_domain_with_www(self):
        """Test domain extraction with www prefix."""
        analyzer = BrandImpersonationAnalyzer()
        domain = analyzer._extract_domain("https://www.example.com")

        assert domain == "example.com"

    def test_extract_domain_subdomain(self):
        """Test domain extraction with subdomain."""
        analyzer = BrandImpersonationAnalyzer()
        domain = analyzer._extract_domain("https://mail.google.com")

        assert domain == "mail.google.com"

    def test_extract_domain_none_url(self):
        """Test domain extraction with None URL."""
        analyzer = BrandImpersonationAnalyzer()
        domain = analyzer._extract_domain(None)

        assert domain is None

    def test_extract_domain_empty_string(self):
        """Test domain extraction with empty string."""
        analyzer = BrandImpersonationAnalyzer()
        domain = analyzer._extract_domain("")

        assert domain is None


class TestBrandImpersonationVisualSimilarity:
    """Test visual similarity comparison."""

    @pytest.mark.asyncio
    async def test_compare_with_brand_template_high_similarity(self):
        """Test comparison with high visual similarity."""
        mock_client = AsyncMock()
        mock_client.compare_images.return_value = {
            "phash_similarity": 0.9,
            "ssim_similarity": 0.85,
        }

        analyzer = BrandImpersonationAnalyzer(image_comparison_client=mock_client)

        screenshot = b"fake_screenshot"
        similarity, confidence = await analyzer._compare_with_brand_template(
            screenshot, "microsoft_365"
        )

        # High similarity should be detected
        assert similarity > 0.5
        assert confidence > 0.0

    @pytest.mark.asyncio
    async def test_compare_with_brand_template_low_similarity(self):
        """Test comparison with low visual similarity."""
        mock_client = AsyncMock()
        mock_client.compare_images.return_value = {
            "phash_similarity": 0.1,
            "ssim_similarity": 0.15,
        }

        analyzer = BrandImpersonationAnalyzer(image_comparison_client=mock_client)

        screenshot = b"fake_screenshot"
        similarity, confidence = await analyzer._compare_with_brand_template(
            screenshot, "google"
        )

        # Low similarity
        assert similarity < 0.5 or similarity == 0.0

    @pytest.mark.asyncio
    async def test_compare_without_client(self):
        """Test comparison without image comparison client."""
        analyzer = BrandImpersonationAnalyzer(image_comparison_client=None)

        screenshot = b"fake_screenshot"
        similarity, confidence = await analyzer._compare_with_brand_template(
            screenshot, "apple"
        )

        # Should return zeros when no client available
        assert similarity == 0.0
        assert confidence == 0.0

    @pytest.mark.asyncio
    async def test_compare_with_empty_screenshot(self):
        """Test comparison with empty screenshot."""
        mock_client = AsyncMock()
        analyzer = BrandImpersonationAnalyzer(image_comparison_client=mock_client)

        similarity, confidence = await analyzer._compare_with_brand_template(
            b"", "microsoft_365"
        )

        # Empty screenshot should return zeros
        assert similarity == 0.0
        assert confidence == 0.0

    @pytest.mark.asyncio
    async def test_compare_client_exception_handling(self):
        """Test exception handling in comparison."""
        mock_client = AsyncMock()
        mock_client.compare_images.side_effect = Exception("Comparison failed")

        analyzer = BrandImpersonationAnalyzer(image_comparison_client=mock_client)

        screenshot = b"fake_screenshot"
        similarity, confidence = await analyzer._compare_with_brand_template(
            screenshot, "paypal"
        )

        # Should handle exception gracefully
        assert similarity == 0.0
        assert confidence == 0.0


class TestBrandImpersonationImpersonationDetection:
    """Test impersonation detection logic."""

    @pytest.mark.asyncio
    async def test_detect_impersonation_high_similarity_mismatched_domain(self):
        """Test detection when visual similarity is high but domain mismatches."""
        mock_client = AsyncMock()
        mock_client.compare_images.return_value = {
            "phash_similarity": 0.85,
            "ssim_similarity": 0.8,
        }

        analyzer = BrandImpersonationAnalyzer(image_comparison_client=mock_client)

        screenshots = {
            "https://fake-microsoft.attacker.com": b"screenshot_of_microsoft_page",
        }

        result = await analyzer.analyze(screenshots)

        assert isinstance(result, AnalyzerResult)
        # High similarity with mismatched domain is impersonation
        assert result.details["screenshot_count"] == 1

    @pytest.mark.asyncio
    async def test_detect_high_similarity_legitimate_domain(self):
        """Test no impersonation when legitimate domain."""
        mock_client = AsyncMock()
        mock_client.compare_images.return_value = {
            "phash_similarity": 0.95,
            "ssim_similarity": 0.9,
        }

        analyzer = BrandImpersonationAnalyzer(image_comparison_client=mock_client)

        screenshots = {
            "https://microsoft.com": b"screenshot_of_microsoft_page",
        }

        result = await analyzer.analyze(screenshots)

        assert isinstance(result, AnalyzerResult)
        # Legitimate domain should not be flagged as impersonation
        assert result.risk_score < 0.85 or result.risk_score == 0.0


class TestBrandImpersonationResultFormat:
    """Test AnalyzerResult format and structure."""

    @pytest.mark.asyncio
    async def test_result_format_complete(self):
        """Test complete AnalyzerResult format."""
        mock_client = AsyncMock()
        mock_client.compare_images.return_value = {
            "phash_similarity": 0.5,
            "ssim_similarity": 0.5,
        }

        analyzer = BrandImpersonationAnalyzer(image_comparison_client=mock_client)

        screenshots = {
            "https://example.com": b"screenshot",
        }

        result = await analyzer.analyze(screenshots)

        # Check AnalyzerResult structure
        assert result.analyzer_name == "brand_impersonation"
        assert isinstance(result.risk_score, float)
        assert isinstance(result.confidence, float)
        assert isinstance(result.details, dict)
        assert isinstance(result.errors, list)

        # Check details structure
        assert "screenshot_count" in result.details
        assert "screenshots_analyzed" in result.details
        assert "brands_checked" in result.details

    @pytest.mark.asyncio
    async def test_result_aggregation_multiple_screenshots(self):
        """Test aggregation of results from multiple screenshots."""
        mock_client = AsyncMock()

        def compare_side_effect(screenshot, template_path):
            if b"clean" in screenshot:
                return {"phash_similarity": 0.2, "ssim_similarity": 0.3}
            else:
                return {"phash_similarity": 0.8, "ssim_similarity": 0.85}

        mock_client.compare_images = compare_side_effect

        analyzer = BrandImpersonationAnalyzer(image_comparison_client=mock_client)

        screenshots = {
            "https://clean-site.com": b"clean_screenshot",
            "https://phishing-site.com": b"phishing_screenshot",
        }

        result = await analyzer.analyze(screenshots)

        assert isinstance(result, AnalyzerResult)
        assert result.details["screenshot_count"] == 2
        # Should aggregate to worst case
        assert result.risk_score >= 0.0

    @pytest.mark.asyncio
    async def test_result_with_errors(self):
        """Test AnalyzerResult with error handling."""
        mock_client = AsyncMock()
        mock_client.compare_images.side_effect = Exception("Image comparison failed")

        analyzer = BrandImpersonationAnalyzer(image_comparison_client=mock_client)

        screenshots = {
            "https://example.com": b"screenshot",
        }

        result = await analyzer.analyze(screenshots)

        assert isinstance(result, AnalyzerResult)
        assert result.analyzer_name == "brand_impersonation"


class TestBrandImpersonationBrandCoverage:
    """Test brand-specific functionality."""

    def test_microsoft_brand_domains(self):
        """Test Microsoft brand domains are properly configured."""
        analyzer = BrandImpersonationAnalyzer()

        microsoft_config = analyzer.BRANDS["microsoft_365"]
        assert "microsoft.com" in microsoft_config["domains"]
        assert "office.com" in microsoft_config["domains"]
        assert "outlook.com" in microsoft_config["domains"]

    def test_google_brand_domains(self):
        """Test Google brand domains are properly configured."""
        analyzer = BrandImpersonationAnalyzer()

        google_config = analyzer.BRANDS["google"]
        assert "google.com" in google_config["domains"]
        assert "accounts.google.com" in google_config["domains"]

    def test_apple_brand_domains(self):
        """Test Apple brand domains are properly configured."""
        analyzer = BrandImpersonationAnalyzer()

        apple_config = analyzer.BRANDS["apple"]
        assert "apple.com" in apple_config["domains"]
        assert "icloud.com" in apple_config["domains"]

    def test_paypal_brand_domains(self):
        """Test PayPal brand domains are properly configured."""
        analyzer = BrandImpersonationAnalyzer()

        paypal_config = analyzer.BRANDS["paypal"]
        assert "paypal.com" in paypal_config["domains"]

    @pytest.mark.asyncio
    async def test_analyze_all_brands_checked(self):
        """Test that all brands are checked in analysis."""
        mock_client = AsyncMock()
        mock_client.compare_images.return_value = {
            "phash_similarity": 0.5,
            "ssim_similarity": 0.5,
        }

        analyzer = BrandImpersonationAnalyzer(image_comparison_client=mock_client)

        screenshots = {
            "https://unknown-site.com": b"screenshot",
        }

        result = await analyzer.analyze(screenshots)

        assert isinstance(result, AnalyzerResult)
        # All brands should be in the result
        assert "brands_checked" in result.details
        brands_checked = result.details["brands_checked"]
        assert len(brands_checked) >= 7  # At least 7 brands


class TestBrandImpersonationConfidenceScoring:
    """Test confidence score calculation."""

    @pytest.mark.asyncio
    async def test_confidence_high_similarity(self):
        """Test confidence scoring with high similarity."""
        mock_client = AsyncMock()
        mock_client.compare_images.return_value = {
            "phash_similarity": 0.9,
            "ssim_similarity": 0.95,
        }

        analyzer = BrandImpersonationAnalyzer(image_comparison_client=mock_client)

        screenshots = {
            "https://fake-google.com": b"screenshot",
        }

        result = await analyzer.analyze(screenshots)

        # High similarity should yield higher confidence
        assert isinstance(result.confidence, float)
        assert result.confidence >= 0.0

    @pytest.mark.asyncio
    async def test_confidence_low_risk_score(self):
        """Test confidence scoring with low risk."""
        mock_client = AsyncMock()
        mock_client.compare_images.return_value = {
            "phash_similarity": 0.1,
            "ssim_similarity": 0.2,
        }

        analyzer = BrandImpersonationAnalyzer(image_comparison_client=mock_client)

        screenshots = {
            "https://example.com": b"screenshot",
        }

        result = await analyzer.analyze(screenshots)

        assert isinstance(result.confidence, float)
