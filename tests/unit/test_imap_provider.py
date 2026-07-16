from unittest.mock import MagicMock

from src.config import IMAPConfig
from src.ingestion.imap_provider import IMAPProvider


def _provider_with_connection():
    provider = IMAPProvider(
        IMAPConfig(
            host="imap.example.com",
            port=993,
            user="owner@example.com",
            password="test-app-password",
        )
    )
    connection = MagicMock()
    provider._authenticated = True
    provider._fetcher._ensure_connected = MagicMock(return_value=connection)
    return provider, connection


def test_fetch_uses_body_peek_and_keeps_message_unread():
    provider, connection = _provider_with_connection()
    provider._fetcher.fetch_new_uids = MagicMock(return_value=["uid-1"])
    connection.uid.return_value = (
        "OK",
        [(b"1 (BODY[] {44}", b"From: vendor@example.com\r\n\r\nInvoice due")],
    )

    fetched = provider.fetch_new_emails(max_results=1)

    assert [item.provider_id for item in fetched] == ["uid-1"]
    connection.uid.assert_called_once_with("fetch", "uid-1", "(BODY.PEEK[])")
    assert all(call.args[0] != "store" for call in connection.uid.call_args_list)


def test_mark_as_read_reports_provider_rejection():
    provider, connection = _provider_with_connection()
    connection.uid.return_value = ("NO", [b"permission denied"])

    marked = provider.mark_as_read("uid-1")

    assert marked is False
    connection.select.assert_called_once_with("INBOX", readonly=False)
    connection.uid.assert_called_once_with("store", "uid-1", "+FLAGS", "\\Seen")
