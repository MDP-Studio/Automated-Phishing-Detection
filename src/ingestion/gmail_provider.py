"""
Gmail provider — connects to Gmail via OAuth2 API.

Setup (one-time):
1. Go to Google Cloud Console → APIs → Enable Gmail API
2. Create OAuth 2.0 Client ID (Desktop app)
3. Download credentials JSON → save as credentials.json
4. Run: python main.py add-account gmail
5. Browser opens → click Allow → token saved automatically

That's it. No passwords, no app passwords, no IMAP config.
"""
import base64
import logging
from pathlib import Path
from typing import Optional

from src.ingestion.email_provider import EmailProvider, FetchedEmail

logger = logging.getLogger(__name__)

SCOPES = [
    "https://www.googleapis.com/auth/gmail.readonly",
    "https://www.googleapis.com/auth/gmail.modify",
]


class GmailProvider(EmailProvider):
    """Gmail API provider with OAuth2."""

    def __init__(
        self,
        credentials_path: str = "credentials.json",
        token_path: str = "data/gmail_token.json",
        user_email: str = "",
    ):
        self._credentials_path = credentials_path
        self._token_path = token_path
        self._user_email = user_email
        self._service = None
        self._creds = None

    @property
    def account_id(self) -> str:
        return self._user_email or "gmail-default"

    @property
    def provider_type(self) -> str:
        return "gmail"

    def authenticate(self, headless: bool = False) -> bool:
        try:
            from google.auth.transport.requests import Request
            from google.oauth2.credentials import Credentials
            from google_auth_oauthlib.flow import InstalledAppFlow
            from googleapiclient.discovery import build
        except ImportError:
            logger.error(
                "Gmail dependencies missing. Run:\n"
                "  pip install google-auth google-auth-oauthlib google-api-python-client"
            )
            return False

        creds = None
        token_path = Path(self._token_path)

        if token_path.exists():
            try:
                creds = Credentials.from_authorized_user_file(str(token_path), SCOPES)
            except Exception as e:
                logger.warning(f"Token load failed: {e}")

        if creds and creds.expired and creds.refresh_token:
            try:
                creds.refresh(Request())
            except Exception:
                creds = None

        if not creds or not creds.valid:
            if not Path(self._credentials_path).exists():
                logger.error(
                    f"Credentials file not found: {self._credentials_path}\n"
                    "Download from Google Cloud Console → APIs → Credentials"
                )
                return False

            flow = InstalledAppFlow.from_client_secrets_file(
                self._credentials_path, SCOPES
            )
            creds = flow.run_console() if headless else flow.run_local_server(port=0)

            token_path.parent.mkdir(parents=True, exist_ok=True)
            with open(token_path, "w") as f:
                f.write(creds.to_json())

        self._creds = creds
        self._service = build("gmail", "v1", credentials=creds)

        # Get the actual email address
        profile = self._service.users().getProfile(userId="me").execute()
        self._user_email = profile.get("emailAddress", self._user_email)
        logger.info(f"Gmail authenticated: {self._user_email}")
        return True

    @property
    def is_authenticated(self) -> bool:
        return self._service is not None

    def fetch_new_emails(self, max_results: int = 20) -> list[FetchedEmail]:
        if not self._service:
            raise RuntimeError("Not authenticated")

        try:
            response = (
                self._service.users()
                .messages()
                .list(userId="me", q="is:unread in:inbox", maxResults=max_results)
                .execute()
            )
        except Exception as e:
            logger.error(f"Gmail list failed: {e}")
            return []

        messages = response.get("messages", [])
        results = []

        for msg_ref in messages:
            try:
                msg = (
                    self._service.users()
                    .messages()
                    .get(userId="me", id=msg_ref["id"], format="raw")
                    .execute()
                )
                raw = base64.urlsafe_b64decode(msg.get("raw", ""))
                results.append(FetchedEmail(
                    provider_id=msg_ref["id"],
                    account_id=self._user_email,
                    raw_bytes=raw,
                    provider_type="gmail",
                    metadata={"threadId": msg_ref.get("threadId")},
                ))
            except Exception as e:
                logger.error(f"Failed to fetch Gmail msg {msg_ref['id']}: {e}")

        return results

    def mark_as_read(self, provider_id: str) -> bool:
        if not self._service:
            return False
        try:
            self._service.users().messages().modify(
                userId="me", id=provider_id,
                body={"removeLabelIds": ["UNREAD"]}
            ).execute()
            return True
        except Exception as e:
            logger.error(f"Gmail mark_as_read failed: {e}")
            return False

    def quarantine(self, provider_id: str, destination: str) -> bool:
        if not self._service:
            return False

        label_id = self._get_or_create_label(destination)
        if not label_id:
            return False

        try:
            self._service.users().messages().modify(
                userId="me", id=provider_id,
                body={"addLabelIds": [label_id], "removeLabelIds": ["INBOX"]}
            ).execute()
            return True
        except Exception as e:
            logger.error(f"Gmail quarantine failed: {e}")
            return False

    def _get_or_create_label(self, name: str) -> Optional[str]:
        try:
            labels = self._service.users().labels().list(userId="me").execute()
            for label in labels.get("labels", []):
                if label["name"].lower() == name.lower():
                    return label["id"]

            result = self._service.users().labels().create(
                userId="me",
                body={"name": name, "labelListVisibility": "labelShow", "messageListVisibility": "show"}
            ).execute()
            return result["id"]
        except Exception as e:
            logger.error(f"Label get/create failed: {e}")
            return None
