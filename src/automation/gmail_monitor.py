"""
Gmail-based email monitoring service.

Two operating modes:
1. **Polling** (default): Checks Gmail API every N seconds for unread emails.
   Simple, works everywhere, no extra infrastructure.

2. **Push** (advanced): Uses Google Cloud Pub/Sub to receive instant
   notifications when new emails arrive. Near-zero latency, but requires
   a Pub/Sub topic and a publicly reachable webhook endpoint.

Usage:
    # Polling mode (simple):
    python main.py monitor --gmail

    # Push mode (advanced, needs Pub/Sub):
    python main.py monitor --gmail --push

    # Or from code:
    monitor = GmailMonitor.from_config(config)
    await monitor.run()
"""
import asyncio
import base64
import json
import logging
import signal
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Optional

from src.config import PipelineConfig
from src.extractors.eml_parser import EMLParser
from src.ingestion.gmail_client import GmailClient
from src.models import EmailObject, PipelineResult, Verdict
from src.orchestrator.pipeline import PhishingPipeline
from src.automation.email_monitor import (
    AlertDispatcher,
    ResultStore,
    ALERT_VERDICTS,
)

logger = logging.getLogger(__name__)


class GmailMonitor:
    """
    Monitors a Gmail inbox and analyzes every incoming email.

    Lifecycle:
    1. Authenticate with Gmail API (OAuth2 token)
    2. Poll for unread emails / receive push notifications
    3. Parse each email → run through PhishingPipeline
    4. Store result → alert if phishing → quarantine (move to label)
    5. Mark as read so it's not re-processed
    """

    def __init__(
        self,
        pipeline: PhishingPipeline,
        gmail_client: GmailClient,
        parser: Optional[EMLParser] = None,
        alert_dispatcher: Optional[AlertDispatcher] = None,
        result_store: Optional[ResultStore] = None,
        poll_interval: int = 30,
        quarantine_label: str = "Quarantine",
    ):
        self.pipeline = pipeline
        self.gmail = gmail_client
        self.parser = parser or EMLParser()
        self.alerts = alert_dispatcher or AlertDispatcher()
        self.store = result_store or ResultStore()
        self.poll_interval = poll_interval
        self.quarantine_label = quarantine_label
        self._running = False
        self._processed_ids: set[str] = set()
        self._stats = {
            "started_at": None,
            "emails_processed": 0,
            "phishing_detected": 0,
            "quarantined": 0,
            "errors": 0,
            "last_poll": None,
            "mode": "polling",
        }
        self._recent_results: list[dict] = []
        self._MAX_RECENT = 200

    @classmethod
    def from_config(cls, config: PipelineConfig) -> "GmailMonitor":
        """Create a GmailMonitor from PipelineConfig."""
        import os

        pipeline = PhishingPipeline(config)

        gmail_client = GmailClient(
            credentials_path=os.getenv("GMAIL_CREDENTIALS_PATH", "credentials.json"),
            token_path=os.getenv("GMAIL_TOKEN_PATH", "data/gmail_token.json"),
        )

        alert_dispatcher = AlertDispatcher()
        alert_dispatcher.set_alert_log("data/alerts.jsonl")

        webhook_url = os.getenv("ALERT_WEBHOOK_URL")
        if webhook_url:
            alert_dispatcher.set_webhook(webhook_url)

        result_store = ResultStore(
            db_path=config.feedback_db_path,
            jsonl_path="data/results.jsonl",
        )

        return cls(
            pipeline=pipeline,
            gmail_client=gmail_client,
            alert_dispatcher=alert_dispatcher,
            result_store=result_store,
            poll_interval=int(os.getenv("GMAIL_POLL_INTERVAL", "30")),
            quarantine_label=os.getenv("GMAIL_QUARANTINE_LABEL", "Quarantine"),
        )

    async def run(self, max_iterations: Optional[int] = None):
        """
        Start the Gmail monitoring loop (polling mode).

        Args:
            max_iterations: Stop after N poll cycles (None = forever)
        """
        # Authenticate
        if not self.gmail.is_authenticated:
            if not self.gmail.authenticate():
                logger.error("Gmail authentication failed. Run: python main.py gmail-auth")
                return

        self._running = True
        self._stats["started_at"] = datetime.now(timezone.utc).isoformat()
        self._stats["mode"] = "polling"
        iteration = 0

        # Signal handlers
        loop = asyncio.get_running_loop()
        for sig in (signal.SIGINT, signal.SIGTERM):
            try:
                loop.add_signal_handler(sig, self.stop)
            except NotImplementedError:
                pass

        logger.info(
            f"Gmail monitor started (polling mode, interval={self.poll_interval}s, "
            f"quarantine_label='{self.quarantine_label}')"
        )

        while self._running:
            if max_iterations is not None and iteration >= max_iterations:
                break

            try:
                await self._poll_and_analyze()
                self._stats["last_poll"] = datetime.now(timezone.utc).isoformat()
            except Exception as e:
                logger.error(f"Poll cycle error: {e}", exc_info=True)
                self._stats["errors"] += 1

            iteration += 1

            if self._running:
                await asyncio.sleep(self.poll_interval)

        logger.info(
            f"Gmail monitor stopped. Stats: "
            f"processed={self._stats['emails_processed']}, "
            f"phishing={self._stats['phishing_detected']}, "
            f"quarantined={self._stats['quarantined']}, "
            f"errors={self._stats['errors']}"
        )

    async def _poll_and_analyze(self):
        """Single poll cycle: fetch unread emails, analyze each."""
        try:
            raw_messages = self.gmail.fetch_new_emails(
                max_results=20,
                query="is:unread in:inbox",
            )
        except Exception as e:
            logger.error(f"Gmail fetch failed: {e}")
            raise

        # Filter out already-processed
        new_messages = [
            m for m in raw_messages if m["id"] not in self._processed_ids
        ]

        if new_messages:
            logger.info(f"Processing {len(new_messages)} new email(s)")

        for msg in new_messages:
            await self._process_single(msg)

    async def _process_single(self, msg: dict):
        """Analyze a single Gmail message."""
        msg_id = msg["id"]
        quarantined = False
        email_obj = None
        result = None

        try:
            # Parse raw RFC822 bytes into EmailObject
            raw_bytes = msg.get("raw_bytes")
            if not raw_bytes:
                raw_bytes = self.gmail.get_email_raw(msg_id)
            if not raw_bytes:
                logger.error(f"Could not fetch raw email for {msg_id}")
                self._stats["errors"] += 1
                return

            email_obj = self.parser.parse_bytes(raw_bytes)
            if not email_obj:
                logger.error(f"Could not parse email {msg_id}")
                self._stats["errors"] += 1
                return

            logger.info(
                f"Analyzing: id={msg_id}, "
                f"from={email_obj.from_address}, "
                f"subject='{email_obj.subject}'"
            )

            # Run pipeline
            result = await self.pipeline.analyze(email_obj)
            self._stats["emails_processed"] += 1
            self._processed_ids.add(msg_id)

            logger.info(
                f"Result: verdict={result.verdict.value}, "
                f"score={result.overall_score:.3f}"
            )

            # Store
            await self.store.store(email_obj, result)

            # Mark as read
            self.gmail.mark_as_read(msg_id)

            # Alert + quarantine if phishing
            if result.verdict in ALERT_VERDICTS:
                self._stats["phishing_detected"] += 1
                await self.alerts.dispatch(email_obj, result)

                # Move to quarantine label
                ok = self.gmail.move_to_label(msg_id, self.quarantine_label)
                if ok:
                    quarantined = True
                    self._stats["quarantined"] += 1
                    logger.info(
                        f"Quarantined email {msg_id} → label '{self.quarantine_label}'"
                    )
                else:
                    logger.warning(f"Failed to quarantine email {msg_id}")

        except Exception as e:
            logger.error(f"Failed to analyze email {msg_id}: {e}", exc_info=True)
            self._stats["errors"] += 1

        # Track in recent results
        record = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "email_id": getattr(email_obj, "email_id", msg_id) if email_obj else msg_id,
            "gmail_id": msg_id,
            "from": getattr(email_obj, "from_address", "unknown") if email_obj else "unknown",
            "subject": getattr(email_obj, "subject", "") if email_obj else "",
            "verdict": result.verdict.value if result else "ERROR",
            "score": result.overall_score if result else 0.0,
            "quarantined": quarantined,
        }
        self._recent_results.append(record)
        if len(self._recent_results) > self._MAX_RECENT:
            self._recent_results.pop(0)

    async def handle_push_notification(self, data: dict) -> dict:
        """
        Handle a Gmail push notification from Pub/Sub.

        This is called by the webhook endpoint when Google pushes
        a notification that new mail has arrived.

        Args:
            data: Decoded Pub/Sub message data containing
                  {"emailAddress": "...", "historyId": "..."}

        Returns:
            Dict with processing results
        """
        history_id = data.get("historyId")
        if not history_id:
            return {"error": "No historyId in push data"}

        # Get new message IDs since this history point
        new_ids = self.gmail.get_history(history_id)
        if not new_ids:
            return {"processed": 0}

        # Filter already-processed
        new_ids = [mid for mid in new_ids if mid not in self._processed_ids]

        results = []
        for msg_id in new_ids:
            raw_bytes = self.gmail.get_email_raw(msg_id)
            if raw_bytes:
                await self._process_single({
                    "id": msg_id,
                    "raw_bytes": raw_bytes,
                })
                results.append(msg_id)

        return {"processed": len(results), "message_ids": results}

    def stop(self):
        """Signal the monitor to stop."""
        logger.info("Gmail monitor shutdown requested")
        self._running = False

    @property
    def stats(self) -> dict:
        return dict(self._stats)
