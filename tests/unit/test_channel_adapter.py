from datetime import datetime, timezone

import pytest

from src.eval.harness import PerSampleRow, aggregate_rows_by_channel
from src.extractors.url_extractor import URLExtractor
from src.ingestion.channel_adapter import ChannelAdapterError, adapt_channel_payload
from src.models import MessageChannel


def test_sms_channel_normalizes_to_email_object_with_stable_id():
    payload = {
        "channel": "sms",
        "sender": "+61400111222",
        "recipients": ["+61400999888"],
        "text": "ATO refund waiting at https://refund.example.test/login",
        "timestamp": "2026-05-08T01:02:03+00:00",
        "platform": "telco-gateway",
    }

    first = adapt_channel_payload(payload)
    second = adapt_channel_payload(payload)

    assert first.email_id == second.email_id
    assert first.channel == MessageChannel.SMS
    assert first.channel_metadata.platform == "telco-gateway"
    assert first.body_plain == payload["text"]
    assert first.attachments == []


def test_chat_and_voice_transcript_normalize_without_email_headers():
    chat = adapt_channel_payload({
        "channel": "chat",
        "sender": "helpdesk-bot",
        "to": "alex",
        "message": "Use the secure chat code now",
        "timestamp": "2026-05-08T01:02:03Z",
    })
    voice = adapt_channel_payload({
        "channel": "voice_transcript",
        "sender": "callback queue",
        "transcript": "Call back our billing desk before 5pm",
        "timestamp": datetime(2026, 5, 8, 1, 2, 3, tzinfo=timezone.utc),
    })

    assert chat.to_addresses == ["alex"]
    assert chat.channel == MessageChannel.CHAT
    assert voice.subject.startswith("Voice transcript lure")
    assert voice.channel == MessageChannel.VOICE_TRANSCRIPT


def test_channel_payload_preserves_url_extraction_continuity():
    email = adapt_channel_payload({
        "channel": "sms",
        "sender": "Bank",
        "text": "Card locked. Visit https://bank.example.test/unlock now.",
        "timestamp": "2026-05-08T01:02:03+00:00",
    })

    urls = URLExtractor().extract_all(plaintext=email.body_plain, html=email.body_html)

    assert [item.url for item in urls] == ["https://bank.example.test/unlock"]


def test_channel_adapter_canonicalizes_offset_timestamps_to_utc():
    email = adapt_channel_payload({
        "channel": "chat",
        "sender": "support",
        "message": "Please approve the helpdesk callback",
        "timestamp": "2026-05-08T11:02:03+10:00",
    })

    assert email.date.isoformat() == "2026-05-08T01:02:03"
    assert email.channel_metadata.received_at == "2026-05-08T01:02:03+00:00"
    assert email.raw_headers["date"][0].endswith("+0000")


def test_channel_adapter_rejects_empty_or_unknown_payloads():
    with pytest.raises(ChannelAdapterError):
        adapt_channel_payload({"channel": "sms", "text": "   "})
    with pytest.raises(ChannelAdapterError):
        adapt_channel_payload({"channel": "fax", "text": "test"})


def test_mixed_eval_channel_metrics_report_false_negatives_by_channel():
    rows = [
        PerSampleRow(
            sample_id="sms-1",
            true_label="PHISHING",
            predicted_verdict="CLEAN",
            predicted_label="CLEAN",
            overall_score=0.1,
            overall_confidence=0.8,
            per_analyzer_scores={},
            calibration_fired=[],
            calibration_cap=None,
            model_id="",
            commit_sha="abc",
            timestamp="2026-05-08T00:00:00+00:00",
            true_positive=False,
            false_positive=False,
            true_negative=False,
            false_negative=True,
            channel="sms",
        ),
        PerSampleRow(
            sample_id="email-1",
            true_label="CLEAN",
            predicted_verdict="CLEAN",
            predicted_label="CLEAN",
            overall_score=0.1,
            overall_confidence=0.8,
            per_analyzer_scores={},
            calibration_fired=[],
            calibration_cap=None,
            model_id="",
            commit_sha="abc",
            timestamp="2026-05-08T00:00:00+00:00",
            true_positive=False,
            false_positive=False,
            true_negative=True,
            false_negative=False,
            channel="email",
        ),
    ]

    metrics = aggregate_rows_by_channel(rows, "permissive")

    assert metrics["sms"]["false_negative"] == 1
    assert metrics["email"]["true_negative"] == 1
