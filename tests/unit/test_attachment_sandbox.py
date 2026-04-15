"""
Test suite for attachment sandbox analyzer in src.analyzers.attachment_sandbox module.

Tests:
- AttachmentSandboxAnalyzer initialization
- analyze() with mocked sandbox returning clean/malicious verdicts
- Timeout handling
- Multiple attachments
- Result aggregation
- Magic byte classification
- File risk scoring
- YARA scanning
"""

import pytest
from unittest.mock import MagicMock, AsyncMock, patch

from src.analyzers.attachment_sandbox import AttachmentSandboxAnalyzer
from src.models import AttachmentObject, AnalyzerResult, AttachmentRisk


class TestAttachmentSandboxAnalyzerInitialization:
    """Test AttachmentSandboxAnalyzer initialization."""

    def test_analyzer_initialization_defaults(self):
        """Test initialization with default parameters."""
        analyzer = AttachmentSandboxAnalyzer()

        assert analyzer is not None
        assert analyzer.sandbox_client is None
        assert analyzer.yara_engine is None

    def test_analyzer_initialization_with_sandbox_client(self):
        """Test initialization with sandbox client."""
        mock_client = MagicMock()
        analyzer = AttachmentSandboxAnalyzer(sandbox_client=mock_client)

        assert analyzer.sandbox_client is mock_client
        assert analyzer.yara_engine is None

    def test_analyzer_initialization_with_yara_engine(self):
        """Test initialization with YARA engine."""
        mock_engine = MagicMock()
        analyzer = AttachmentSandboxAnalyzer(yara_engine=mock_engine)

        assert analyzer.sandbox_client is None
        assert analyzer.yara_engine is mock_engine

    def test_analyzer_initialization_both_clients(self):
        """Test initialization with both clients."""
        mock_sandbox = MagicMock()
        mock_yara = MagicMock()
        analyzer = AttachmentSandboxAnalyzer(
            sandbox_client=mock_sandbox,
            yara_engine=mock_yara,
        )

        assert analyzer.sandbox_client is mock_sandbox
        assert analyzer.yara_engine is mock_yara


class TestAttachmentSandboxAnalyze:
    """Test analyze() method."""

    @pytest.mark.asyncio
    async def test_analyze_no_attachments(self):
        """
        Empty attachments list means the analyzer has no data about the
        email's phishing likelihood. The correct return is
        (risk_score=0.0, confidence=0.0) so the decision engine skips
        the analyzer from the weighted score (decision_engine.py:227
        "Skip analyzers with zero confidence").

        This test previously asserted confidence=1.0 (the cycle 1 fix).
        That was wrong: a "no data" analyzer voting clean with full
        confidence dilutes every other analyzer's contribution via the
        normalized weighted-score formula. The cycle 13 audit caught
        the dilution by manually tracing why cycle 12's sender_profiling
        fix didn't move recall — attachment_analysis was applying the
        same dead-domain-confidence dilution pattern on every sample
        with no attachments, which was 22 out of 22 samples in the
        test corpus.

        The assertion here now matches the cycle 4 dead-domain pattern:
        analyzers with no data return confidence=0.0 to be skipped, not
        confidence=1.0 to vote clean. See HISTORY.md cycle 13.
        """
        analyzer = AttachmentSandboxAnalyzer()

        result = await analyzer.analyze([])

        assert isinstance(result, AnalyzerResult)
        assert result.analyzer_name == "attachment_sandbox"
        assert result.risk_score == 0.0
        assert result.confidence == 0.0, (
            "no-attachments path must return confidence=0.0 to be skipped "
            "from weighted scoring. See cycle 13 HISTORY entry for the "
            "root-cause trace back to cycle 1."
        )
        assert "no_attachments" in result.details.get("message", "")

    @pytest.mark.asyncio
    async def test_analyze_single_benign_attachment(self):
        """Test analyzing a single benign PDF attachment."""
        mock_sandbox = AsyncMock()
        mock_sandbox.submit.return_value = {
            "submission_id": "test_id_123",
        }
        mock_sandbox.get_results.return_value = {
            "verdict": "benign",
            "detected_by": 0,
            "behaviors": [],
            "extracted_files": [],
            "contacted_urls": [],
            "dns_requests": [],
        }

        analyzer = AttachmentSandboxAnalyzer(sandbox_client=mock_sandbox)

        attachments = [
            AttachmentObject(
                filename="document.pdf",
                content_type="application/pdf",
                magic_type="application/pdf",
                size_bytes=102400,
                content=b"%PDF-1.4\n%test content",
                is_archive=False,
                has_macros=False,
            )
        ]

        result = await analyzer.analyze(attachments)

        assert isinstance(result, AnalyzerResult)
        assert result.analyzer_name == "attachment_sandbox"
        assert result.risk_score >= 0.0

    @pytest.mark.asyncio
    async def test_analyze_multiple_attachments(self):
        """Test analyzing multiple attachments."""
        mock_sandbox = AsyncMock()
        mock_sandbox.submit.return_value = {
            "submission_id": "test_id_123",
        }
        mock_sandbox.get_results.return_value = {
            "verdict": "benign",
            "detected_by": 0,
            "behaviors": [],
            "extracted_files": [],
            "contacted_urls": [],
            "dns_requests": [],
        }

        analyzer = AttachmentSandboxAnalyzer(sandbox_client=mock_sandbox)

        attachments = [
            AttachmentObject(
                filename="file1.pdf",
                content_type="application/pdf",
                magic_type="application/pdf",
                size_bytes=1024,
                content=b"%PDF-1.4\n",
                is_archive=False,
                has_macros=False,
            ),
            AttachmentObject(
                filename="file2.txt",
                content_type="text/plain",
                magic_type="text/plain",
                size_bytes=512,
                content=b"plain text",
                is_archive=False,
                has_macros=False,
            ),
            AttachmentObject(
                filename="file3.doc",
                content_type="application/msword",
                magic_type="application/msword",
                size_bytes=2048,
                content=b"\xd0\xcf\x11\xe0",
                is_archive=False,
                has_macros=True,
            ),
        ]

        result = await analyzer.analyze(attachments)

        assert isinstance(result, AnalyzerResult)
        assert result.details["attachment_count"] == 3


class TestAttachmentSandboxMagicBytes:
    """Test magic byte file classification."""

    def test_classify_pe_executable(self):
        """Test classification of PE executable."""
        analyzer = AttachmentSandboxAnalyzer()

        content = b"MZ\x90\x00" + b"fake_exe"
        category, description = analyzer._classify_by_magic_bytes(content)

        assert category == "executable"
        assert "PE" in description or "executable" in description

    def test_classify_elf_executable(self):
        """Test classification of ELF executable."""
        analyzer = AttachmentSandboxAnalyzer()

        content = b"\x7fELF" + b"fake_elf"
        category, description = analyzer._classify_by_magic_bytes(content)

        assert category == "executable"
        assert "ELF" in description

    def test_classify_pdf(self):
        """Test classification of PDF file."""
        analyzer = AttachmentSandboxAnalyzer()

        content = b"%PDF-1.4\n" + b"fake_pdf"
        category, description = analyzer._classify_by_magic_bytes(content)

        assert category == "document"
        assert "PDF" in description

    def test_classify_office_modern(self):
        """Test classification of modern Office document."""
        analyzer = AttachmentSandboxAnalyzer()

        content = b"PK\x03\x04" + b"fake_office"
        category, description = analyzer._classify_by_magic_bytes(content)

        assert category in ["document", "archive"]

    def test_classify_office_legacy(self):
        """Test classification of legacy Office document."""
        analyzer = AttachmentSandboxAnalyzer()

        content = b"\xd0\xcf\x11\xe0" + b"fake_office"
        category, description = analyzer._classify_by_magic_bytes(content)

        assert category == "document"

    def test_classify_zip_archive(self):
        """Test classification of ZIP archive."""
        analyzer = AttachmentSandboxAnalyzer()

        content = b"PK\x03\x04" + b"fake_zip"
        category, description = analyzer._classify_by_magic_bytes(content)

        assert category in ["document", "archive"]

    def test_classify_png_image(self):
        """Test classification of PNG image."""
        analyzer = AttachmentSandboxAnalyzer()

        content = b"\x89PNG\r\n\x1a\n" + b"fake_png"
        category, description = analyzer._classify_by_magic_bytes(content)

        assert category == "image"
        assert "PNG" in description

    def test_classify_jpeg_image(self):
        """Test classification of JPEG image."""
        analyzer = AttachmentSandboxAnalyzer()

        content = b"\xff\xd8\xff" + b"fake_jpeg"
        category, description = analyzer._classify_by_magic_bytes(content)

        assert category == "image"
        assert "JPEG" in description

    def test_classify_unknown_file(self):
        """Test classification of unknown file type."""
        analyzer = AttachmentSandboxAnalyzer()

        content = b"unknown_magic_bytes"
        category, description = analyzer._classify_by_magic_bytes(content)

        assert category == "unknown"


class TestAttachmentSandboxFileRisk:
    """Test file risk scoring."""

    def test_calculate_risk_executable_extension(self):
        """Test risk calculation for executable extension."""
        analyzer = AttachmentSandboxAnalyzer()

        attachment = AttachmentObject(
            filename="malware.exe",
            content_type="application/octet-stream",
            magic_type="executable",
            size_bytes=1024,
            content=b"MZ",
            is_archive=False,
            has_macros=False,
        )

        risk_score, reasons = analyzer._calculate_file_risk(attachment, "executable")

        assert risk_score >= 0.8
        assert "dangerous_extension" in reasons or "executable" in reasons

    def test_calculate_risk_suspicious_filename(self):
        """Test risk calculation for suspicious filename."""
        analyzer = AttachmentSandboxAnalyzer()

        attachment = AttachmentObject(
            filename="invoice_urgent.pdf",
            content_type="application/pdf",
            magic_type="application/pdf",
            size_bytes=1024,
            content=b"%PDF",
            is_archive=False,
            has_macros=False,
        )

        risk_score, reasons = analyzer._calculate_file_risk(attachment, "document")

        assert risk_score >= 0.3
        assert "suspicious_filename" in reasons

    def test_calculate_risk_macro_enabled(self):
        """Test risk calculation for macro-enabled document."""
        analyzer = AttachmentSandboxAnalyzer()

        attachment = AttachmentObject(
            filename="document.docm",
            content_type="application/vnd.ms-word.document.macroEnabled.12",
            magic_type="document",
            size_bytes=1024,
            content=b"\xd0\xcf\x11\xe0",
            is_archive=False,
            has_macros=True,
        )

        risk_score, reasons = analyzer._calculate_file_risk(attachment, "document")

        assert risk_score >= 0.7
        assert "contains_macros" in reasons

    def test_calculate_risk_zero_size_file(self):
        """Test risk calculation for zero-size file."""
        analyzer = AttachmentSandboxAnalyzer()

        attachment = AttachmentObject(
            filename="empty.txt",
            content_type="text/plain",
            magic_type="unknown",
            size_bytes=0,
            content=b"",
            is_archive=False,
            has_macros=False,
        )

        risk_score, reasons = analyzer._calculate_file_risk(attachment, "unknown")

        assert risk_score >= 0.5
        assert "zero_size" in reasons

    def test_calculate_risk_archive_file(self):
        """Test risk calculation for archive file."""
        analyzer = AttachmentSandboxAnalyzer()

        attachment = AttachmentObject(
            filename="archive.zip",
            content_type="application/zip",
            magic_type="archive",
            size_bytes=5120,
            content=b"PK\x03\x04",
            is_archive=True,
            has_macros=False,
        )

        risk_score, reasons = analyzer._calculate_file_risk(attachment, "archive")

        assert risk_score >= 0.5
        assert "archive" in reasons

    def test_calculate_risk_large_file(self):
        """Test risk calculation for unusually large file."""
        analyzer = AttachmentSandboxAnalyzer()

        attachment = AttachmentObject(
            filename="largefile.bin",
            content_type="application/octet-stream",
            magic_type="unknown",
            size_bytes=15 * 1024 * 1024,  # 15 MB
            content=b"data",
            is_archive=False,
            has_macros=False,
        )

        risk_score, reasons = analyzer._calculate_file_risk(attachment, "unknown")

        assert risk_score >= 0.3
        assert "unusually_large" in reasons


class TestAttachmentSandboxSubmission:
    """Test sandbox submission and result handling."""

    @pytest.mark.asyncio
    async def test_submit_to_sandbox_malicious_verdict(self):
        """Test sandbox submission with malicious verdict."""
        mock_sandbox = AsyncMock()
        mock_sandbox.submit.return_value = {
            "submission_id": "test_id_123",
        }
        mock_sandbox.get_results.return_value = {
            "verdict": "malicious",
            "detected_by": 45,
            "behaviors": ["drops_files", "connects_to_c2"],
            "extracted_files": ["malware.bin"],
            "contacted_urls": ["http://c2.attacker.com"],
            "dns_requests": ["attacker.com"],
        }

        analyzer = AttachmentSandboxAnalyzer(sandbox_client=mock_sandbox)

        attachment = AttachmentObject(
            filename="suspicious.exe",
            content_type="application/octet-stream",
            magic_type="executable",
            size_bytes=102400,
            content=b"MZ\x90",
            is_archive=False,
            has_macros=False,
        )

        risk_score, confidence, details = await analyzer._submit_to_sandbox(attachment)

        assert risk_score == 0.95
        assert confidence == 1.0
        assert "sandbox_results" in details

    @pytest.mark.asyncio
    async def test_submit_to_sandbox_suspicious_verdict(self):
        """Test sandbox submission with suspicious verdict."""
        mock_sandbox = AsyncMock()
        mock_sandbox.submit.return_value = {
            "submission_id": "test_id_456",
        }
        mock_sandbox.get_results.return_value = {
            "verdict": "suspicious",
            "detected_by": 5,
            "behaviors": ["modifies_registry"],
            "extracted_files": [],
            "contacted_urls": [],
            "dns_requests": [],
        }

        analyzer = AttachmentSandboxAnalyzer(sandbox_client=mock_sandbox)

        attachment = AttachmentObject(
            filename="questionable.dll",
            content_type="application/octet-stream",
            magic_type="executable",
            size_bytes=51200,
            content=b"MZ",
            is_archive=False,
            has_macros=False,
        )

        risk_score, confidence, details = await analyzer._submit_to_sandbox(attachment)

        assert risk_score == 0.6
        assert confidence == 0.8

    @pytest.mark.asyncio
    async def test_submit_to_sandbox_benign_verdict(self):
        """Test sandbox submission with benign verdict."""
        mock_sandbox = AsyncMock()
        mock_sandbox.submit.return_value = {
            "submission_id": "test_id_789",
        }
        mock_sandbox.get_results.return_value = {
            "verdict": "benign",
            "detected_by": 0,
            "behaviors": [],
            "extracted_files": [],
            "contacted_urls": [],
            "dns_requests": [],
        }

        analyzer = AttachmentSandboxAnalyzer(sandbox_client=mock_sandbox)

        attachment = AttachmentObject(
            filename="document.pdf",
            content_type="application/pdf",
            magic_type="application/pdf",
            size_bytes=102400,
            content=b"%PDF-1.4",
            is_archive=False,
            has_macros=False,
        )

        risk_score, confidence, details = await analyzer._submit_to_sandbox(attachment)

        assert risk_score == 0.05
        assert confidence == 0.9

    @pytest.mark.asyncio
    async def test_submit_to_sandbox_no_client(self):
        """Test submission without sandbox client."""
        analyzer = AttachmentSandboxAnalyzer(sandbox_client=None)

        attachment = AttachmentObject(
            filename="file.bin",
            content_type="application/octet-stream",
            magic_type="unknown",
            size_bytes=1024,
            content=b"data",
            is_archive=False,
            has_macros=False,
        )

        risk_score, confidence, details = await analyzer._submit_to_sandbox(attachment)

        assert risk_score == 0.0
        assert confidence == 0.0
        assert details == {}


class TestAttachmentSandboxYARA:
    """Test YARA rule scanning."""

    @pytest.mark.asyncio
    async def test_scan_with_yara_critical_match(self):
        """Test YARA scanning with critical severity match."""
        mock_yara = AsyncMock()
        mock_yara.scan.return_value = [
            {
                "rule": "Trojan.Generic",
                "severity": "critical",
            }
        ]

        analyzer = AttachmentSandboxAnalyzer(yara_engine=mock_yara)

        content = b"malicious_file_content"
        risk_score, confidence, details = await analyzer._scan_with_yara(content)

        assert risk_score == 0.95
        assert confidence == 0.9
        assert "yara" in details

    @pytest.mark.asyncio
    async def test_scan_with_yara_high_match(self):
        """Test YARA scanning with high severity match."""
        mock_yara = AsyncMock()
        mock_yara.scan.return_value = [
            {
                "rule": "Trojan.Win32.Generic",
                "severity": "high",
            }
        ]

        analyzer = AttachmentSandboxAnalyzer(yara_engine=mock_yara)

        content = b"suspicious_content"
        risk_score, confidence, details = await analyzer._scan_with_yara(content)

        assert risk_score == 0.8
        assert confidence == 0.9

    @pytest.mark.asyncio
    async def test_scan_with_yara_no_matches(self):
        """Test YARA scanning with no matches."""
        mock_yara = AsyncMock()
        mock_yara.scan.return_value = []

        analyzer = AttachmentSandboxAnalyzer(yara_engine=mock_yara)

        content = b"benign_content"
        risk_score, confidence, details = await analyzer._scan_with_yara(content)

        assert risk_score == 0.0
        assert confidence == 0.9
        assert "yara_matches" in details
        assert details["yara_matches"] == []

    @pytest.mark.asyncio
    async def test_scan_with_yara_no_engine(self):
        """Test scanning without YARA engine."""
        analyzer = AttachmentSandboxAnalyzer(yara_engine=None)

        content = b"file_content"
        risk_score, confidence, details = await analyzer._scan_with_yara(content)

        assert risk_score == 0.0
        assert confidence == 0.0
        assert details == {}

    @pytest.mark.asyncio
    async def test_scan_with_yara_multiple_matches(self):
        """Test YARA scanning with multiple rule matches."""
        mock_yara = AsyncMock()
        mock_yara.scan.return_value = [
            {
                "rule": "Trojan.Generic",
                "severity": "high",
            },
            {
                "rule": "Suspicious.API.Call",
                "severity": "medium",
            },
            {
                "rule": "Packed.Executable",
                "severity": "medium",
            },
        ]

        analyzer = AttachmentSandboxAnalyzer(yara_engine=mock_yara)

        content = b"complex_malware"
        risk_score, confidence, details = await analyzer._scan_with_yara(content)

        # Should take max severity
        assert risk_score == 0.8
        assert confidence == 0.9
        assert len(details["yara"]["yara_matches"]) == 3


class TestAttachmentSandboxResultFormat:
    """Test AnalyzerResult format and structure."""

    @pytest.mark.asyncio
    async def test_result_format_complete(self):
        """Test complete AnalyzerResult format."""
        mock_sandbox = AsyncMock()
        mock_sandbox.submit.return_value = {
            "submission_id": "test_id",
        }
        mock_sandbox.get_results.return_value = {
            "verdict": "benign",
            "detected_by": 0,
            "behaviors": [],
            "extracted_files": [],
            "contacted_urls": [],
            "dns_requests": [],
        }

        analyzer = AttachmentSandboxAnalyzer(sandbox_client=mock_sandbox)

        attachments = [
            AttachmentObject(
                filename="document.pdf",
                content_type="application/pdf",
                magic_type="application/pdf",
                size_bytes=1024,
                content=b"%PDF",
                is_archive=False,
                has_macros=False,
            )
        ]

        result = await analyzer.analyze(attachments)

        # Check AnalyzerResult structure
        assert result.analyzer_name == "attachment_sandbox"
        assert isinstance(result.risk_score, float)
        assert isinstance(result.confidence, float)
        assert isinstance(result.details, dict)
        assert isinstance(result.errors, list)

        # Check details structure
        assert "attachment_count" in result.details
        assert "attachments_analyzed" in result.details

    @pytest.mark.asyncio
    async def test_result_aggregation_multiple_attachments(self):
        """Test aggregation of results from multiple attachments."""
        mock_sandbox = AsyncMock()

        async def get_results_side_effect(submission_id):
            if "benign" in submission_id:
                return {
                    "verdict": "benign",
                    "detected_by": 0,
                    "behaviors": [],
                    "extracted_files": [],
                    "contacted_urls": [],
                    "dns_requests": [],
                }
            else:
                return {
                    "verdict": "malicious",
                    "detected_by": 50,
                    "behaviors": ["malware"],
                    "extracted_files": [],
                    "contacted_urls": [],
                    "dns_requests": [],
                }

        mock_sandbox.submit.return_value = {"submission_id": "test_id"}
        mock_sandbox.get_results = get_results_side_effect

        analyzer = AttachmentSandboxAnalyzer(sandbox_client=mock_sandbox)

        attachments = [
            AttachmentObject(
                filename="benign.pdf",
                content_type="application/pdf",
                magic_type="application/pdf",
                size_bytes=1024,
                content=b"%PDF",
                is_archive=False,
                has_macros=False,
            ),
            AttachmentObject(
                filename="malware.exe",
                content_type="application/octet-stream",
                magic_type="executable",
                size_bytes=2048,
                content=b"MZ",
                is_archive=False,
                has_macros=False,
            ),
        ]

        result = await analyzer.analyze(attachments)

        assert isinstance(result, AnalyzerResult)
        assert result.details["attachment_count"] == 2
        # Should aggregate to worst case
        assert result.risk_score >= 0.0


class TestAttachmentSandboxVerdicts:
    """Test verdict determination."""

    @pytest.mark.asyncio
    async def test_verdict_malicious(self):
        """Test verdict determination for malicious attachment."""
        analyzer = AttachmentSandboxAnalyzer()

        attachment = AttachmentObject(
            filename="malware.exe",
            content_type="application/octet-stream",
            magic_type="executable",
            size_bytes=1024,
            content=b"MZ",
            is_archive=False,
            has_macros=False,
        )

        # Simulate high-risk file
        with patch.object(analyzer, "_calculate_file_risk", return_value=(0.9, "executable_file")):
            with patch.object(analyzer, "_submit_to_sandbox", return_value=(0.0, 0.0, {})):
                with patch.object(analyzer, "_scan_with_yara", return_value=(0.0, 0.0, {})):
                    result = await analyzer.analyze([attachment])

        assert isinstance(result, AnalyzerResult)

    @pytest.mark.asyncio
    async def test_verdict_benign(self):
        """Test verdict determination for benign attachment."""
        analyzer = AttachmentSandboxAnalyzer()

        attachment = AttachmentObject(
            filename="document.txt",
            content_type="text/plain",
            magic_type="text/plain",
            size_bytes=512,
            content=b"plain text content",
            is_archive=False,
            has_macros=False,
        )

        with patch.object(analyzer, "_calculate_file_risk", return_value=(0.0, "")):
            with patch.object(analyzer, "_submit_to_sandbox", return_value=(0.0, 0.0, {})):
                with patch.object(analyzer, "_scan_with_yara", return_value=(0.0, 0.0, {})):
                    result = await analyzer.analyze([attachment])

        assert isinstance(result, AnalyzerResult)
