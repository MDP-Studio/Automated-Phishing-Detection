"""
Gmail API client with OAuth2 authentication.

Replaces IMAP for Gmail users with a simpler auth flow:
1. User runs `python main.py gmail-auth`
2. Browser opens, user clicks "Allow"
3. OAuth token saved to data/gmail_token.json
4. Monitor uses token to fetch emails — no passwords needed

Supports:
- OAuth2 web/installed app flow
- Token refresh (automatic)
- Fetch new/unread emails
- Get email by ID (full RFC822)
- Move emails to label (quarantine)
- Gmail push notifications (watch/stop)

Requires:
    pip install google-auth google-auth-oauthlib google-api-python-client
"""
import base64
import json
import logging
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)

# Gmail API scopes needed
SCOPES = [
    "https://www.googleapis.com/auth/gmail.readonly",
    "https://www.googleapis.com/auth/gmail.modify",  # move/label
]


class GmailClient:
    """
    Gmail API client with OAuth2 authentication.

    Usage:
        client = GmailClient(credentials_path="credentials.json")
        client.authenticate()  # opens browser on first run

        # Fetch new unread emails
        emails = client.fetch_new_emails()

        # Move to quarantine label
        client.move_to_label(msg_id, "Quarantine")
    """

    def __init__(
        self,
        credentials_path: str = "credentials.json",
        token_path: str = "data/gmail_token.json",
        user_id: str = "me",
    ):
        """
        Args:
            credentials_path: Path to Google OAuth2 credentials JSON
                (download from Google Cloud Console → APIs & Services → Credentials)
            token_path: Path to store/load the OAuth2 token
            user_id: Gmail user ID ('me' for authenticated user)
        """
        self.credentials_path = credentials_path
        self.token_path = token_path
        self.user_id = user_id
        self._service = None
        self._creds = None

    def authenticate(self, headless: bool = False) -> bool:
        """
        Authenticate with Gmail API via OAuth2.

        On first run, opens a browser for the user to authorize.
        On subsequent runs, uses the saved token (refreshing if expired).

        Args:
            headless: If True, print the auth URL instead of opening browser
                (for server/Docker deployments)

        Returns:
            True if authentication succeeded
        """
        try:
            from google.auth.transport.requests import Request
            from google.oauth2.credentials import Credentials
            from google_auth_oauthlib.flow import InstalledAppFlow
            from googleapiclient.discovery import build
        except ImportError:
            logger.error(
                "Gmail API dependencies not installed. Run:\n"
                "  pip install google-auth google-auth-oauthlib google-api-python-client"
            )
            return False

        creds = None

        # Load existing token
        token_path = Path(self.token_path)
        if token_path.exists():
            try:
                creds = Credentials.from_authorized_user_file(
                    str(token_path), SCOPES
                )
                logger.info("Loaded existing Gmail token")
            except Exception as e:
                logger.warning(f"Failed to load token: {e}")

        # Refresh or re-authenticate
        if creds and creds.expired and creds.refresh_token:
            try:
                creds.refresh(Request())
                logger.info("Refreshed Gmail token")
            except Exception as e:
                logger.warning(f"Token refresh failed, re-authenticating: {e}")
                creds = None

        if not creds or not creds.valid:
            if not Path(self.credentials_path).exists():
                logger.error(
                    f"Gmail credentials file not found: {self.credentials_path}\n"
                    "Download it from Google Cloud Console → APIs & Services → Credentials\n"
                    "Create an OAuth 2.0 Client ID (Desktop app), download JSON, save as credentials.json"
                )
                return False

            flow = InstalledAppFlow.from_client_secrets_file(
                self.credentials_path, SCOPES
            )

            if headless:
                # For server deployments: print URL, user pastes code
                creds = flow.run_console()
            else:
                creds = flow.run_local_server(port=0)

            # Save token for next run
            token_path.parent.mkdir(parents=True, exist_ok=True)
            with open(token_path, "w") as f:
                f.write(creds.to_json())
            logger.info(f"Saved Gmail token to {token_path}")

        self._creds = creds
        self._service = build("gmail", "v1", credentials=creds)
        logger.info("Gmail API client ready")
        return True

    @property
    def is_authenticated(self) -> bool:
        return self._service is not None

    def fetch_new_emails(
        self,
        max_results: int = 20,
        query: str = "is:unread",
        since: Optional[datetime] = None,
    ) -> list[dict]:
        """
        Fetch new/unread emails from Gmail.

        Args:
            max_results: Max emails to return per call
            query: Gmail search query (default: unread)
            since: Only emails after this datetime

        Returns:
            List of dicts with keys: id, threadId, snippet, raw_message
        """
        if not self._service:
            raise RuntimeError("Not authenticated. Call authenticate() first.")

        # Build query
        q = query
        if since:
            # Gmail uses epoch seconds for after: filter
            epoch = int(since.timestamp())
            q += f" after:{epoch}"

        try:
            response = (
                self._service.users()
                .messages()
                .list(userId=self.user_id, q=q, maxResults=max_results)
                .execute()
            )
        except Exception as e:
            logger.error(f"Gmail list failed: {e}")
            return []

        messages = response.get("messages", [])
        if not messages:
            return []

        logger.info(f"Found {len(messages)} matching emails")

        results = []
        for msg_ref in messages:
            msg_data = self.get_email_raw(msg_ref["id"])
            if msg_data:
                results.append({
                    "id": msg_ref["id"],
                    "threadId": msg_ref.get("threadId"),
                    "raw_bytes": msg_data,
                })

        return results

    def get_email_raw(self, msg_id: str) -> Optional[bytes]:
        """
        Get the full RFC822 raw email bytes by message ID.

        Args:
            msg_id: Gmail message ID

        Returns:
            Raw email bytes, or None on failure
        """
        if not self._service:
            raise RuntimeError("Not authenticated")

        try:
            msg = (
                self._service.users()
                .messages()
                .get(
                    userId=self.user_id,
                    id=msg_id,
                    format="raw",
                )
                .execute()
            )
            raw = msg.get("raw", "")
            return base64.urlsafe_b64decode(raw)
        except Exception as e:
            logger.error(f"Failed to fetch message {msg_id}: {e}")
            return None

    def mark_as_read(self, msg_id: str) -> bool:
        """Mark a message as read (remove UNREAD label)."""
        return self._modify_labels(msg_id, remove_labels=["UNREAD"])

    def move_to_label(self, msg_id: str, label_name: str) -> bool:
        """
        Move email to a label (Gmail's equivalent of folders).

        Creates the label if it doesn't exist.

        Args:
            msg_id: Gmail message ID
            label_name: Label to move to (e.g., "Quarantine")

        Returns:
            True on success
        """
        label_id = self._get_or_create_label(label_name)
        if not label_id:
            return False

        # Add quarantine label + remove from INBOX
        return self._modify_labels(
            msg_id,
            add_labels=[label_id],
            remove_labels=["INBOX"],
        )

    def _modify_labels(
        self,
        msg_id: str,
        add_labels: Optional[list[str]] = None,
        remove_labels: Optional[list[str]] = None,
    ) -> bool:
        """Modify labels on a message."""
        if not self._service:
            return False

        body = {}
        if add_labels:
            body["addLabelIds"] = add_labels
        if remove_labels:
            body["removeLabelIds"] = remove_labels

        try:
            self._service.users().messages().modify(
                userId=self.user_id, id=msg_id, body=body
            ).execute()
            return True
        except Exception as e:
            logger.error(f"Failed to modify labels for {msg_id}: {e}")
            return False

    def _get_or_create_label(self, label_name: str) -> Optional[str]:
        """Get label ID by name, creating it if needed."""
        if not self._service:
            return None

        try:
            # List existing labels
            response = (
                self._service.users().labels().list(userId=self.user_id).execute()
            )
            for label in response.get("labels", []):
                if label["name"].lower() == label_name.lower():
                    return label["id"]

            # Create new label
            label_body = {
                "name": label_name,
                "labelListVisibility": "labelShow",
                "messageListVisibility": "show",
            }
            result = (
                self._service.users()
                .labels()
                .create(userId=self.user_id, body=label_body)
                .execute()
            )
            logger.info(f"Created Gmail label: {label_name} (id={result['id']})")
            return result["id"]

        except Exception as e:
            logger.error(f"Failed to get/create label '{label_name}': {e}")
            return None

    def setup_push_notifications(
        self,
        topic_name: str,
        label_ids: Optional[list[str]] = None,
    ) -> Optional[dict]:
        """
        Set up Gmail push notifications via Google Cloud Pub/Sub.

        When a new email arrives, Google pushes a notification to your
        Pub/Sub topic. Your webhook receives it and triggers analysis.

        Prerequisites:
        1. Create a Pub/Sub topic in Google Cloud Console
        2. Grant gmail-api-push@system.gserviceaccount.com publish permission
        3. Create a push subscription pointing to your webhook URL

        Args:
            topic_name: Full Pub/Sub topic (e.g., "projects/my-project/topics/gmail-push")
            label_ids: Labels to watch (default: ["INBOX"])

        Returns:
            Watch response with historyId and expiration, or None on failure
        """
        if not self._service:
            return None

        body = {
            "topicName": topic_name,
            "labelIds": label_ids or ["INBOX"],
        }

        try:
            response = (
                self._service.users().watch(userId=self.user_id, body=body).execute()
            )
            logger.info(
                f"Gmail push notifications active. "
                f"historyId={response.get('historyId')}, "
                f"expiration={response.get('expiration')}"
            )
            return response
        except Exception as e:
            logger.error(f"Failed to set up push notifications: {e}")
            return None

    def stop_push_notifications(self) -> bool:
        """Stop Gmail push notifications."""
        if not self._service:
            return False
        try:
            self._service.users().stop(userId=self.user_id).execute()
            logger.info("Gmail push notifications stopped")
            return True
        except Exception as e:
            logger.error(f"Failed to stop push notifications: {e}")
            return False

    def get_history(self, start_history_id: str) -> list[dict]:
        """
        Get email changes since a history ID (used with push notifications).

        Args:
            start_history_id: History ID from push notification or watch response

        Returns:
            List of new message IDs added since that history point
        """
        if not self._service:
            return []

        try:
            response = (
                self._service.users()
                .history()
                .list(
                    userId=self.user_id,
                    startHistoryId=start_history_id,
                    historyTypes=["messageAdded"],
                    labelId="INBOX",
                )
                .execute()
            )

            new_msg_ids = []
            for record in response.get("history", []):
                for added in record.get("messagesAdded", []):
                    new_msg_ids.append(added["message"]["id"])

            return new_msg_ids

        except Exception as e:
            logger.error(f"Failed to get history since {start_history_id}: {e}")
            return []
