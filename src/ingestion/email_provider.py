"""
Abstract email provider interface for multi-account support.

Providers implement a common interface so the monitor doesn't care
whether emails come from Gmail, Outlook, Yahoo, or generic IMAP.

Each provider handles:
- Authentication (OAuth2, credentials, etc.)
- Fetching new/unread emails as raw RFC822 bytes
- Marking emails as read
- Moving emails to quarantine (folder/label)

Supported providers:
- GmailProvider: Google Gmail API + OAuth2
- OutlookProvider: Microsoft Graph API + OAuth2
- IMAPProvider: Any IMAP server (Yahoo, ProtonMail, self-hosted, etc.)
"""
import logging
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Optional

logger = logging.getLogger(__name__)


@dataclass
class FetchedEmail:
    """
    A raw email fetched from a provider.

    This is the common output from all providers before parsing.
    """
    provider_id: str          # provider-specific ID (Gmail msg ID, IMAP UID, etc.)
    account_id: str           # which account this came from (e.g., "user@gmail.com")
    raw_bytes: bytes          # full RFC822 email bytes
    provider_type: str = ""   # "gmail", "outlook", "imap"
    metadata: dict = field(default_factory=dict)  # provider-specific extras


class EmailProvider(ABC):
    """
    Abstract interface for email providers.

    Subclasses must implement all abstract methods.
    """

    @property
    @abstractmethod
    def account_id(self) -> str:
        """Unique identifier for this account (usually the email address)."""
        ...

    @property
    @abstractmethod
    def provider_type(self) -> str:
        """Provider type string: 'gmail', 'outlook', 'imap'."""
        ...

    @abstractmethod
    def authenticate(self) -> bool:
        """
        Authenticate with the email service.

        Returns:
            True if authentication succeeded
        """
        ...

    @property
    @abstractmethod
    def is_authenticated(self) -> bool:
        """Whether the provider is currently authenticated."""
        ...

    @abstractmethod
    def fetch_new_emails(self, max_results: int = 20) -> list[FetchedEmail]:
        """
        Fetch new/unread emails.

        Args:
            max_results: Maximum number of emails to return

        Returns:
            List of FetchedEmail objects
        """
        ...

    @abstractmethod
    def mark_as_read(self, provider_id: str) -> bool:
        """
        Mark an email as read so it won't be re-fetched.

        Args:
            provider_id: Provider-specific message ID

        Returns:
            True on success
        """
        ...

    @abstractmethod
    def quarantine(self, provider_id: str, destination: str) -> bool:
        """
        Move an email to quarantine (folder, label, etc.).

        Args:
            provider_id: Provider-specific message ID
            destination: Quarantine folder/label name

        Returns:
            True on success
        """
        ...

    def disconnect(self):
        """Optional cleanup. Override if needed."""
        pass

    def __repr__(self):
        return f"<{self.__class__.__name__} account={self.account_id}>"
