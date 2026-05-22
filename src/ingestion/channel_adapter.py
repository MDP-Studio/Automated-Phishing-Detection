"""Normalize email, SMS, chat, and voice transcript inputs for analyzers."""
from __future__ import annotations
import logging

import base64
import hashlib
import json
from datetime import datetime, timezone
from email.utils import format_datetime
from typing import Any

from src.extractors.eml_parser import EMLParser
from src.models import ChannelMetadata, EmailObject, MessageChannel, utc_now

logger = logging.getLogger(__name__)

CHANNEL_MAX_TEXT_CHARS = 50000
TEXT_CHANNELS = {
    MessageChannel.SMS,
    MessageChannel.CHAT,
    MessageChannel.VOICE_TRANSCRIPT,
}


class ChannelAdapterError(ValueError):
    """Raised when a channel payload cannot be normalized."""


def parse_message_channel(value: Any) -> MessageChannel:
    raw = str(value or MessageChannel.EMAIL.value).strip().lower().replace("-", "_")
    aliases = {
        "voice": MessageChannel.VOICE_TRANSCRIPT.value,
        "transcript": MessageChannel.VOICE_TRANSCRIPT.value,
        "voice_transcript": MessageChannel.VOICE_TRANSCRIPT.value,
        "text": MessageChannel.SMS.value,
        "txt": MessageChannel.SMS.value,
        "im": MessageChannel.CHAT.value,
        "instant_message": MessageChannel.CHAT.value,
    }
    raw = aliases.get(raw, raw)
    try:
        return MessageChannel(raw)
    except ValueError as exc:
        allowed = ", ".join(channel.value for channel in MessageChannel)
        raise ChannelAdapterError(f"Unsupported message channel. Use one of: {allowed}") from exc


def adapt_email_bytes(raw: bytes, *, source: str = "email_upload") -> EmailObject:
    parser = EMLParser()
    email = parser.parse_bytes(raw)
    if email is None:
        raise ChannelAdapterError("Could not parse email payload")
    email.channel = MessageChannel.EMAIL
    email.channel_metadata = ChannelMetadata(source=source, direction="inbound")
    return email


def adapt_channel_payload(payload: dict[str, Any]) -> EmailObject:
    if not isinstance(payload, dict):
        raise ChannelAdapterError("Channel payload must be a JSON object")

    channel = parse_message_channel(payload.get("channel"))
    if channel == MessageChannel.EMAIL:
        raw_email = payload.get("raw_email")
        if raw_email is None:
            raise ChannelAdapterError("Email channel JSON requires raw_email. Use .eml upload otherwise.")
        if isinstance(raw_email, str):
            raw = _decode_raw_email(raw_email)
        elif isinstance(raw_email, bytes):
            raw = raw_email
        else:
            raise ChannelAdapterError("raw_email must be a string or bytes value")
        return adapt_email_bytes(raw, source=str(payload.get("source") or "channel_json"))

    if channel not in TEXT_CHANNELS:
        raise ChannelAdapterError(f"Unsupported text channel: {channel.value}")

    text = _first_nonempty_text(payload, "text", "body", "transcript", "message")
    if not text:
        raise ChannelAdapterError("Text, body, transcript, or message is required")
    if len(text) > CHANNEL_MAX_TEXT_CHARS:
        raise ChannelAdapterError(f"Channel text exceeds {CHANNEL_MAX_TEXT_CHARS} character limit")

    sender = str(payload.get("sender") or payload.get("from") or "unknown-sender").strip()
    recipients = _coerce_recipients(payload.get("recipients", payload.get("to")))
    platform = str(payload.get("platform") or payload.get("service") or "").strip()
    conversation_id = str(payload.get("conversation_id") or payload.get("thread_id") or "").strip()
    direction = str(payload.get("direction") or "inbound").strip().lower()
    source = str(payload.get("source") or "json_channel_scan").strip()
    received_at = _received_at(payload)
    received_utc = received_at.astimezone(timezone.utc)
    subject = str(payload.get("subject") or _default_subject(channel, sender)).strip()
    if len(subject) > 180:
        subject = subject[:177].rstrip() + "..."

    email_id = _stable_channel_id(
        channel=channel,
        text=text,
        sender=sender,
        recipients=recipients,
        subject=subject,
        platform=platform,
        conversation_id=conversation_id,
        received_at=received_utc.isoformat(),
    )
    message_id = f"<{email_id}@channel.phishanalyze.local>"
    raw_headers = {
        "x-message-channel": [channel.value],
        "x-channel-source": [source],
        "x-channel-platform": [platform],
        "from": [sender],
        "to": recipients,
        "subject": [subject],
        "date": [format_datetime(received_utc)],
    }

    return EmailObject(
        email_id=email_id,
        raw_headers=raw_headers,
        from_address=sender,
        from_display_name=str(payload.get("sender_display_name") or sender),
        reply_to=None,
        to_addresses=recipients,
        cc_addresses=[],
        subject=subject,
        body_plain=text,
        body_html="",
        date=received_utc.replace(tzinfo=None),
        attachments=[],
        inline_images=[],
        message_id=message_id,
        received_chain=[],
        channel=channel,
        channel_metadata=ChannelMetadata(
            source=source,
            platform=platform,
            conversation_id=conversation_id,
            sender=sender,
            recipients=recipients,
            direction=direction or "inbound",
            received_at=received_utc.isoformat(),
        ),
    )


def channel_public_payload(email: EmailObject) -> dict[str, Any]:
    metadata = getattr(email, "channel_metadata", None)
    return {
        "channel": getattr(getattr(email, "channel", MessageChannel.EMAIL), "value", "email"),
        "metadata": {
            "source": getattr(metadata, "source", ""),
            "platform": getattr(metadata, "platform", ""),
            "conversation_id": getattr(metadata, "conversation_id", ""),
            "sender": getattr(metadata, "sender", ""),
            "recipients": list(getattr(metadata, "recipients", []) or []),
            "direction": getattr(metadata, "direction", "inbound"),
            "received_at": getattr(metadata, "received_at", None),
        },
    }


def _first_nonempty_text(payload: dict[str, Any], *keys: str) -> str:
    for key in keys:
        value = payload.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
    return ""


def _coerce_recipients(value: Any) -> list[str]:
    if value is None or value == "":
        return []
    if isinstance(value, str):
        return [value.strip()] if value.strip() else []
    if isinstance(value, list):
        recipients = []
        for item in value:
            text = str(item).strip()
            if text:
                recipients.append(text)
        return recipients
    text = str(value).strip()
    return [text] if text else []


def _received_at(payload: dict[str, Any]) -> datetime:
    raw = payload.get("received_at") or payload.get("timestamp") or payload.get("date")
    if not raw:
        return utc_now().replace(tzinfo=timezone.utc)
    if isinstance(raw, datetime):
        return raw if raw.tzinfo else raw.replace(tzinfo=timezone.utc)
    value = str(raw).strip()
    if not value:
        return utc_now().replace(tzinfo=timezone.utc)
    if value.endswith("Z"):
        value = value[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError as exc:
        raise ChannelAdapterError("received_at, timestamp, or date must be ISO-8601") from exc
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


def _default_subject(channel: MessageChannel, sender: str) -> str:
    label = {
        MessageChannel.SMS: "SMS lure",
        MessageChannel.CHAT: "Chat lure",
        MessageChannel.VOICE_TRANSCRIPT: "Voice transcript lure",
    }.get(channel, "Message lure")
    return f"{label} from {sender or 'unknown sender'}"


def _stable_channel_id(**parts: Any) -> str:
    canonical = json.dumps(parts, sort_keys=True, separators=(",", ":"), default=str)
    digest = hashlib.sha256(canonical.encode("utf-8")).hexdigest()[:32]
    return f"channel-{digest}"


def _decode_raw_email(raw_email: str) -> bytes:
    text = raw_email.strip()
    if text.startswith("base64:"):
        text = text.split(":", 1)[1]
    try:
        return base64.b64decode(text, validate=True)
    except Exception:
        logger.debug("Suppressed exception in src/ingestion/channel_adapter.py", exc_info=True)
        return raw_email.encode("utf-8")
