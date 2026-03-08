"""
Test suite for QR code decoder in src.extractors.qr_decoder module.

Tests:
- QRCodeDecoder initialization
- Decoding from raw image bytes
- URL extraction from QR codes
- Image preprocessing variants
- Multiple QR codes in single image
- Missing dependencies handling
- DecodingConfig customization
"""

import io
import pytest
from unittest.mock import MagicMock, patch, AsyncMock
import numpy as np

from src.extractors.qr_decoder import QRDecoder, DecodingConfig
from src.models import EmailObject, AttachmentObject, ExtractedURL, URLSource


class TestQRDecoderInitialization:
    """Test QRDecoder initialization and configuration."""

    def test_decoder_initialization_default_config(self):
        """Test QR decoder initialization with default config."""
        decoder = QRDecoder()
        assert decoder is not None
        assert decoder.config is not None
        assert decoder.config.resize_factor == 2
        assert decoder.config.enable_adaptive_threshold is True

    def test_decoder_initialization_custom_config(self):
        """Test QR decoder initialization with custom configuration."""
        config = DecodingConfig(
            resize_factor=3,
            enable_adaptive_threshold=False,
            enable_sharpening=True,
            min_url_length=10,
            max_url_length=1024,
        )
        decoder = QRDecoder(config)
        assert decoder.config.resize_factor == 3
        assert decoder.config.enable_adaptive_threshold is False
        assert decoder.config.min_url_length == 10

    def test_decoder_config_default_values(self):
        """Test default values in DecodingConfig."""
        config = DecodingConfig()
        assert config.pdf_dpi == 200
        assert config.extract_pdf_images is True
        assert config.extract_pdf_renders is True
        assert config.deduplicate_by_resolved is True

    def test_decoder_validate_dependencies(self):
        """Test dependency validation logging."""
        decoder = QRDecoder()
        # Should not raise exception
        assert decoder is not None


class TestQRDecoderFromImageBytes:
    """Test decoding from raw image bytes."""

    @patch("src.extractors.qr_decoder.HAS_PIL", True)
    @patch("src.extractors.qr_decoder.HAS_PYZBAR", True)
    @patch("src.extractors.qr_decoder.Image")
    def test_decode_from_bytes_single_qr_code(self, mock_image):
        """Test decoding a single QR code from image bytes."""
        import src.extractors.qr_decoder as qr_module

        mock_pyzbar = MagicMock()
        qr_module.pyzbar = mock_pyzbar

        mock_img = MagicMock()
        mock_image.open.return_value = mock_img

        mock_decoded = MagicMock()
        mock_decoded.data.decode.return_value = "https://example.com"
        mock_pyzbar.decode.return_value = [mock_decoded]

        decoder = QRDecoder()
        image_bytes = b"fake_image_data"

        with patch("src.extractors.qr_decoder.np.array", return_value=np.zeros((100, 100, 3))):
            with patch.object(decoder, "_preprocess_image", return_value=[np.zeros((100, 100, 3))]):
                urls = decoder.decode_from_image_bytes(image_bytes, "test_source")

        assert len(urls) >= 1
        assert urls[0].url == "https://example.com"
        assert urls[0].source == URLSource.QR_CODE

    @patch("src.extractors.qr_decoder.HAS_PIL", False)
    def test_decode_from_bytes_missing_pil(self):
        """Test decode_from_image_bytes returns empty when PIL unavailable."""
        decoder = QRDecoder()
        image_bytes = b"fake_image_data"

        urls = decoder.decode_from_image_bytes(image_bytes, "test_source")

        assert urls == []

    @patch("src.extractors.qr_decoder.HAS_PIL", True)
    @patch("src.extractors.qr_decoder.HAS_PYZBAR", False)
    def test_decode_from_bytes_missing_pyzbar(self):
        """Test decode_from_image_bytes returns empty when pyzbar unavailable."""
        decoder = QRDecoder()
        image_bytes = b"fake_image_data"

        urls = decoder.decode_from_image_bytes(image_bytes, "test_source")

        assert urls == []

    @patch("src.extractors.qr_decoder.HAS_PIL", True)
    @patch("src.extractors.qr_decoder.HAS_PYZBAR", True)
    @patch("src.extractors.qr_decoder.Image")
    def test_decode_from_bytes_multiple_qr_codes(self, mock_image):
        """Test decoding multiple QR codes from same image."""
        import src.extractors.qr_decoder as qr_module

        mock_pyzbar = MagicMock()
        qr_module.pyzbar = mock_pyzbar

        mock_img = MagicMock()
        mock_image.open.return_value = mock_img

        mock_decoded1 = MagicMock()
        mock_decoded1.data.decode.return_value = "https://example.com"

        mock_decoded2 = MagicMock()
        mock_decoded2.data.decode.return_value = "https://phishing.com"

        mock_pyzbar.decode.return_value = [mock_decoded1, mock_decoded2]

        decoder = QRDecoder()
        image_bytes = b"fake_image_data"

        with patch("src.extractors.qr_decoder.np.array", return_value=np.zeros((100, 100, 3))):
            with patch.object(decoder, "_preprocess_image", return_value=[np.zeros((100, 100, 3))]):
                urls = decoder.decode_from_image_bytes(image_bytes, "test_source")

        assert len(urls) >= 2
        extracted_urls = [url.url for url in urls]
        assert "https://example.com" in extracted_urls
        assert "https://phishing.com" in extracted_urls


class TestQRDecoderURLValidation:
    """Test URL validation from QR codes."""

    def test_is_url_like_https(self):
        """Test validation of HTTPS URLs."""
        decoder = QRDecoder()
        assert decoder._is_url_like("https://example.com") is True
        assert decoder._is_url_like("http://example.com") is True

    def test_is_url_like_data_uri(self):
        """Test validation of data URIs."""
        decoder = QRDecoder()
        assert decoder._is_url_like("data:image/png;base64,abc123") is True

    def test_is_url_like_tel(self):
        """Test validation of tel: scheme."""
        decoder = QRDecoder()
        assert decoder._is_url_like("tel:+1234567890") is True
        assert decoder._is_url_like("mailto:test@example.com") is True

    def test_is_url_like_domain_heuristic(self):
        """Test heuristic domain validation."""
        decoder = QRDecoder()
        assert decoder._is_url_like("example.com") is True
        assert decoder._is_url_like("subdomain.example.co.uk") is True

    def test_is_url_like_invalid_length(self):
        """Test URL validation with length constraints."""
        config = DecodingConfig(min_url_length=10, max_url_length=100)
        decoder = QRDecoder(config)

        assert decoder._is_url_like("short") is False
        assert decoder._is_url_like("a" * 150) is False

    def test_is_url_like_invalid_domain(self):
        """Test rejection of invalid domains."""
        decoder = QRDecoder()
        assert decoder._is_url_like("notaurl") is False
        assert decoder._is_url_like("just text") is False


class TestQRDecoderImagePreprocessing:
    """Test image preprocessing variants."""

    @patch("src.extractors.qr_decoder.HAS_PIL", True)
    @patch("src.extractors.qr_decoder.HAS_CV2", False)
    def test_preprocess_image_resize_only(self):
        """Test image preprocessing with resize only."""
        decoder = QRDecoder()

        image_array = np.zeros((100, 100, 3), dtype=np.uint8)

        with patch("src.extractors.qr_decoder.Image") as mock_image_class:
            mock_pil_img = MagicMock()
            mock_pil_img.width = 100
            mock_pil_img.height = 100
            mock_image_class.fromarray.return_value = mock_pil_img
            mock_pil_img.resize.return_value = mock_pil_img

            with patch("src.extractors.qr_decoder.np.array", return_value=image_array):
                variants = decoder._preprocess_image(image_array)

        assert len(variants) > 0
        assert all(isinstance(v, np.ndarray) for v in variants)

    @patch("src.extractors.qr_decoder.HAS_PIL", True)
    @patch("src.extractors.qr_decoder.HAS_CV2", True)
    def test_preprocess_image_with_cv2_enabled(self):
        """Test image preprocessing with OpenCV enabled."""
        config = DecodingConfig(
            enable_adaptive_threshold=True,
            enable_sharpening=True,
            enable_contrast=True,
        )
        decoder = QRDecoder(config)

        image_array = np.zeros((100, 100, 3), dtype=np.uint8)

        with patch("src.extractors.qr_decoder.cv2"):
            with patch("src.extractors.qr_decoder.Image"):
                with patch("src.extractors.qr_decoder.ImageEnhance"):
                    with patch("src.extractors.qr_decoder.np.array", return_value=image_array):
                        variants = decoder._preprocess_image(image_array)

        assert isinstance(variants, list)

    def test_preprocess_image_disabled_options(self):
        """Test preprocessing with all options disabled."""
        config = DecodingConfig(
            enable_adaptive_threshold=False,
            enable_sharpening=False,
            enable_contrast=False,
            enable_invert=False,
        )
        decoder = QRDecoder(config)

        image_array = np.zeros((100, 100, 3), dtype=np.uint8)

        variants = decoder._preprocess_image(image_array)
        assert len(variants) > 0


class TestQRDecoderInlineImages:
    """Test decoding from inline email images."""

    @patch("src.extractors.qr_decoder.HAS_PIL", True)
    @patch("src.extractors.qr_decoder.HAS_PYZBAR", True)
    def test_decode_from_inline_images(self, caplog):
        """Test extraction from inline images."""
        decoder = QRDecoder()

        email = EmailObject(
            email_id="test_email",
            raw_headers={},
            from_address="sender@example.com",
            from_display_name="Sender",
            reply_to=None,
            to_addresses=["recipient@example.com"],
            cc_addresses=[],
            subject="Test",
            body_plain="Test body",
            body_html="<html></html>",
            date=None,
            attachments=[],
            inline_images=[b"fake_image_1", b"fake_image_2"],
            message_id="<test@example.com>",
            received_chain=[],
        )

        with patch.object(decoder, "decode_from_image_bytes", return_value=[]):
            urls = decoder.decode_from_inline_images(email)

        assert isinstance(urls, list)


class TestQRDecoderImageAttachments:
    """Test decoding from image attachments."""

    def test_decode_from_image_attachments_png(self):
        """Test extraction from PNG attachments."""
        decoder = QRDecoder()

        png_content = b"\x89PNG\r\n\x1a\n" + b"fake_data" * 100

        email = EmailObject(
            email_id="test_email",
            raw_headers={},
            from_address="sender@example.com",
            from_display_name="Sender",
            reply_to=None,
            to_addresses=["recipient@example.com"],
            cc_addresses=[],
            subject="Test",
            body_plain="Test body",
            body_html="<html></html>",
            date=None,
            attachments=[
                AttachmentObject(
                    filename="image.png",
                    content_type="image/png",
                    magic_type="image/png",
                    size_bytes=len(png_content),
                    content=png_content,
                    is_archive=False,
                    has_macros=False,
                )
            ],
            inline_images=[],
            message_id="<test@example.com>",
            received_chain=[],
        )

        with patch.object(decoder, "decode_from_image_bytes", return_value=[]):
            urls = decoder.decode_from_image_attachments(email)

        assert isinstance(urls, list)

    def test_decode_from_image_attachments_jpeg(self):
        """Test extraction from JPEG attachments."""
        decoder = QRDecoder()

        jpeg_content = b"\xff\xd8\xff" + b"fake_data" * 100

        email = EmailObject(
            email_id="test_email",
            raw_headers={},
            from_address="sender@example.com",
            from_display_name="Sender",
            reply_to=None,
            to_addresses=["recipient@example.com"],
            cc_addresses=[],
            subject="Test",
            body_plain="Test body",
            body_html="<html></html>",
            date=None,
            attachments=[
                AttachmentObject(
                    filename="image.jpg",
                    content_type="image/jpeg",
                    magic_type="image/jpeg",
                    size_bytes=len(jpeg_content),
                    content=jpeg_content,
                    is_archive=False,
                    has_macros=False,
                )
            ],
            inline_images=[],
            message_id="<test@example.com>",
            received_chain=[],
        )

        with patch.object(decoder, "decode_from_image_bytes", return_value=[]):
            urls = decoder.decode_from_image_attachments(email)

        assert isinstance(urls, list)


class TestQRDecoderDeduplication:
    """Test URL deduplication logic."""

    def test_deduplicate_empty_list(self):
        """Test deduplication of empty URL list."""
        decoder = QRDecoder()
        result = decoder._deduplicate([])
        assert result == []

    def test_deduplicate_identical_urls(self):
        """Test deduplication of identical URLs."""
        decoder = QRDecoder()

        urls = [
            ExtractedURL(
                url="https://example.com",
                source=URLSource.QR_CODE,
                source_detail="source1",
            ),
            ExtractedURL(
                url="https://example.com",
                source=URLSource.QR_CODE,
                source_detail="source2",
            ),
        ]

        result = decoder._deduplicate(urls)
        assert len(result) == 1
        assert result[0].url == "https://example.com"

    def test_deduplicate_by_resolved_url(self):
        """Test deduplication by resolved URL."""
        decoder = QRDecoder(DecodingConfig(deduplicate_by_resolved=True))

        urls = [
            ExtractedURL(
                url="https://short.url/abc",
                source=URLSource.QR_CODE,
                source_detail="source1",
                resolved_url="https://example.com/long/path",
            ),
            ExtractedURL(
                url="https://another.short/def",
                source=URLSource.QR_CODE,
                source_detail="source2",
                resolved_url="https://example.com/long/path",
            ),
        ]

        result = decoder._deduplicate(urls)
        assert len(result) == 1

    def test_deduplicate_distinct_urls(self):
        """Test deduplication with distinct URLs."""
        decoder = QRDecoder()

        urls = [
            ExtractedURL(
                url="https://example.com",
                source=URLSource.QR_CODE,
                source_detail="source1",
            ),
            ExtractedURL(
                url="https://different.com",
                source=URLSource.QR_CODE,
                source_detail="source2",
            ),
        ]

        result = decoder._deduplicate(urls)
        assert len(result) == 2


@pytest.mark.asyncio
async def test_decode_all_orchestrator():
    """Test the main async orchestrator method."""
    decoder = QRDecoder()

    email = EmailObject(
        email_id="test_email",
        raw_headers={},
        from_address="sender@example.com",
        from_display_name="Sender",
        reply_to=None,
        to_addresses=["recipient@example.com"],
        cc_addresses=[],
        subject="Test",
        body_plain="Test body",
        body_html="<html></html>",
        date=None,
        attachments=[],
        inline_images=[],
        message_id="<test@example.com>",
        received_chain=[],
    )

    with patch.object(decoder, "decode_from_inline_images", return_value=[]):
        with patch.object(decoder, "decode_from_image_attachments", return_value=[]):
            with patch.object(decoder, "decode_from_pdf_attachments", return_value=[]):
                with patch.object(decoder, "decode_from_docx_attachments", return_value=[]):
                    with patch.object(decoder, "decode_from_html_rendered", new_callable=AsyncMock, return_value=[]):
                        urls = await decoder.decode_all(email)

    assert isinstance(urls, list)
