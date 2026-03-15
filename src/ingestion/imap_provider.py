"""
Generic IMAP provider — works with any email service that supports IMAP.

Works with: Yahoo Mail, ProtonMail Bridge, Zoho, FastMail, self-hosted
Dovecot/Postfix, corporate Exchange (with IMAP enabled), etc.

Setup:
    python main.py add-account imap \\
        --host imap.yahoo.com --port 993 \\
        --user you@yahoo.com
"""
import logging
from typing import Optional

from src.config import IMAPConfig
from src.ingestion.email_provider import EmailProvider, FetchedEmail
from src.ingestion.imap_fetcher import IMAPFetcher

logger = logging.getLogger(__name__)


class IMAPProvider(EmailProvider):
    """
    Generic IMAP provider wrapping the existing IMAPFetcher.

    Works with any email server that supports IMAP over SSL.
    """

    def __init__(self, config: IMAPConfig):
        self._config = config
        self._fetcher = IMAPFetcher(config)
        self._authenticated = False

    @property
    def account_id(self) -> str:
        return f"{self._config.user}@{self._config.host}" if self._config.user else "imap-default"

    @property
    def provider_type(self) -> str:
        return "imap"

    def authenticate(self) -> bool:
        if not self._config.user or not self._config.password:
            logger.error("IMAP user and password required")
            return False

        try:
            self._fetcher.connect()
            self._authenticated = True
            logger.info(f"IMAP authenticated: {self._config.user}@{self._config.host}")
            return True
        except Exception as e:
            logger.error(f"IMAP auth failed: {e}")
            return False

    @property
    def is_authenticated(self) -> bool:
        return self._authenticated

    def fetch_new_emails(self, max_results: int = 20) -> list[FetchedEmail]:
        if not self._authenticated:
            raise RuntimeError("Not authenticated")

        uids = self._fetcher.fetch_new_uids()[:max_results]
        results = []

        for uid in uids:
            conn = self._fetcher._ensure_connected()
            status, data = conn.uid("fetch", uid, "(RFC822)")
            if status != "OK" or not data or data[0] is None:
                continue

            raw_bytes = data[0][1]
            if isinstance(raw_bytes, str):
                raw_bytes = raw_bytes.encode("utf-8", errors="replace")

            self._fetcher._processed_uids.add(uid)

            results.append(FetchedEmail(
                provider_id=uid,
                account_id=self.account_id,
                raw_bytes=raw_bytes,
                provider_type="imap",
                metadata={"folder": self._config.folder},
            ))

        return results

    def mark_as_read(self, provider_id: str) -> bool:
        try:
            conn = self._fetcher._ensure_connected()
            # Need writable access
            conn.select(self._config.folder, readonly=False)
            conn.uid("store", provider_id, "+FLAGS", "\\Seen")
            return True
        except Exception as e:
            logger.error(f"IMAP mark_as_read failed: {e}")
            return False

    def quarantine(self, provider_id: str, destination: str) -> bool:
        try:
            self._fetcher.ensure_folder_exists(destination)
            return self._fetcher.move_to_folder(provider_id, destination)
        except Exception as e:
            logger.error(f"IMAP quarantine failed: {e}")
            return False

    def disconnect(self):
        self._fetcher.disconnect()
        self._authenticated = False
