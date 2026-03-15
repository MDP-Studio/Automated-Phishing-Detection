"""
Microsoft Outlook/365 provider — connects via Microsoft Graph API + OAuth2.

Setup (one-time):
1. Go to Azure Portal → App Registrations → New registration
2. Add redirect URI: http://localhost (Mobile/Desktop)
3. Add API permissions: Mail.Read, Mail.ReadWrite
4. Note the Application (client) ID
5. Run: python main.py add-account outlook
6. Browser opens → sign in → authorize → token saved

Works with: Outlook.com, Office 365, Hotmail, Live.com
"""
import json
import logging
from pathlib import Path
from typing import Optional

from src.ingestion.email_provider import EmailProvider, FetchedEmail

logger = logging.getLogger(__name__)

GRAPH_BASE = "https://graph.microsoft.com/v1.0"
SCOPES = ["https://graph.microsoft.com/Mail.Read", "https://graph.microsoft.com/Mail.ReadWrite"]


class OutlookProvider(EmailProvider):
    """Microsoft Graph API provider with OAuth2."""

    def __init__(
        self,
        client_id: str = "",
        token_path: str = "data/outlook_token.json",
        user_email: str = "",
    ):
        self._client_id = client_id
        self._token_path = token_path
        self._user_email = user_email
        self._session = None  # requests session with auth headers
        self._access_token: Optional[str] = None

    @property
    def account_id(self) -> str:
        return self._user_email or "outlook-default"

    @property
    def provider_type(self) -> str:
        return "outlook"

    def authenticate(self, headless: bool = False) -> bool:
        try:
            import msal
            import requests
        except ImportError:
            logger.error(
                "Outlook dependencies missing. Run:\n"
                "  pip install msal requests"
            )
            return False

        token_path = Path(self._token_path)

        # Try to load cached token
        cache = msal.SerializableTokenCache()
        if token_path.exists():
            cache.deserialize(token_path.read_text())

        app = msal.PublicClientApplication(
            self._client_id,
            authority="https://login.microsoftonline.com/common",
            token_cache=cache,
        )

        # Try silent (cached) first
        accounts = app.get_accounts()
        result = None
        if accounts:
            result = app.acquire_token_silent(SCOPES, account=accounts[0])

        if not result:
            # Interactive flow
            flow = app.initiate_device_flow(scopes=SCOPES)
            if "user_code" not in flow:
                logger.error(f"Device flow failed: {flow.get('error_description')}")
                return False

            print(f"\nTo sign in, open: {flow['verification_uri']}")
            print(f"Enter code: {flow['user_code']}\n")

            result = app.acquire_token_by_device_flow(flow)

        if "access_token" not in result:
            logger.error(f"Auth failed: {result.get('error_description')}")
            return False

        self._access_token = result["access_token"]

        # Save cache
        if cache.has_state_changed:
            token_path.parent.mkdir(parents=True, exist_ok=True)
            token_path.write_text(cache.serialize())

        # Get user profile
        import requests
        headers = {"Authorization": f"Bearer {self._access_token}"}
        resp = requests.get(f"{GRAPH_BASE}/me", headers=headers, timeout=10)
        if resp.ok:
            profile = resp.json()
            self._user_email = profile.get("mail") or profile.get("userPrincipalName", self._user_email)

        self._session = requests.Session()
        self._session.headers.update(headers)

        logger.info(f"Outlook authenticated: {self._user_email}")
        return True

    @property
    def is_authenticated(self) -> bool:
        return self._session is not None

    def fetch_new_emails(self, max_results: int = 20) -> list[FetchedEmail]:
        if not self._session:
            raise RuntimeError("Not authenticated")

        try:
            # Get unread messages from inbox
            resp = self._session.get(
                f"{GRAPH_BASE}/me/mailFolders/inbox/messages",
                params={
                    "$filter": "isRead eq false",
                    "$top": max_results,
                    "$select": "id,subject,from,receivedDateTime",
                },
                timeout=30,
            )
            resp.raise_for_status()
            messages = resp.json().get("value", [])
        except Exception as e:
            logger.error(f"Outlook list failed: {e}")
            return []

        results = []
        for msg in messages:
            raw = self._get_mime_content(msg["id"])
            if raw:
                results.append(FetchedEmail(
                    provider_id=msg["id"],
                    account_id=self._user_email,
                    raw_bytes=raw,
                    provider_type="outlook",
                    metadata={
                        "subject": msg.get("subject"),
                        "receivedDateTime": msg.get("receivedDateTime"),
                    },
                ))

        return results

    def _get_mime_content(self, msg_id: str) -> Optional[bytes]:
        """Get raw MIME content of a message."""
        try:
            resp = self._session.get(
                f"{GRAPH_BASE}/me/messages/{msg_id}/$value",
                timeout=30,
            )
            resp.raise_for_status()
            return resp.content
        except Exception as e:
            logger.error(f"Failed to get MIME for {msg_id}: {e}")
            return None

    def mark_as_read(self, provider_id: str) -> bool:
        if not self._session:
            return False
        try:
            resp = self._session.patch(
                f"{GRAPH_BASE}/me/messages/{provider_id}",
                json={"isRead": True},
                timeout=10,
            )
            return resp.ok
        except Exception as e:
            logger.error(f"Outlook mark_as_read failed: {e}")
            return False

    def quarantine(self, provider_id: str, destination: str) -> bool:
        if not self._session:
            return False

        # Get or create the destination folder
        folder_id = self._get_or_create_folder(destination)
        if not folder_id:
            return False

        try:
            resp = self._session.post(
                f"{GRAPH_BASE}/me/messages/{provider_id}/move",
                json={"destinationId": folder_id},
                timeout=10,
            )
            return resp.ok
        except Exception as e:
            logger.error(f"Outlook quarantine failed: {e}")
            return False

    def _get_or_create_folder(self, name: str) -> Optional[str]:
        try:
            # List folders
            resp = self._session.get(
                f"{GRAPH_BASE}/me/mailFolders",
                params={"$filter": f"displayName eq '{name}'"},
                timeout=10,
            )
            if resp.ok:
                folders = resp.json().get("value", [])
                if folders:
                    return folders[0]["id"]

            # Create folder
            resp = self._session.post(
                f"{GRAPH_BASE}/me/mailFolders",
                json={"displayName": name},
                timeout=10,
            )
            if resp.ok:
                return resp.json()["id"]

        except Exception as e:
            logger.error(f"Folder get/create failed: {e}")

        return None

    def disconnect(self):
        if self._session:
            self._session.close()
            self._session = None
