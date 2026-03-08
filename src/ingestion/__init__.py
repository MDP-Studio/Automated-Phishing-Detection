"""Email ingestion layer — IMAP polling, manual upload, webhook."""
from src.ingestion.imap_fetcher import IMAPFetcher
from src.ingestion.manual_upload import ManualUploadHandler

__all__ = ["IMAPFetcher", "ManualUploadHandler"]
