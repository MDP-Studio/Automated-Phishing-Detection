"""
Persistent email_id -> record lookup over data/results.jsonl.

Implements the design from `docs/adr/0002-persistent-email-id-lookup-for-feedback.md`.
Read the ADR before changing the semantics here; the failure modes are
documented there in detail.

Quick summary:
    - In-memory dict mapping email_id -> byte_offset into results.jsonl
    - Built at startup by walking the file once
    - Updated on every append via `add(email_id, record)` (caller does
      the actual file write; the index just records the offset)
    - Lookup misses trigger a stat-and-reload retry that catches both
      the in-process append window AND external appends from another
      process or worker
    - Atomic-swap retention purge (`src/automation/retention.py`) calls
      `invalidate()` after the swap to force a rebuild on next lookup

The semantic the ADR pins, repeated here so it can't drift away from
the implementation:

    Lookups are eventually consistent within one rebuild cycle
    (typically milliseconds). A lookup that misses immediately after a
    successful append will succeed on retry. A lookup with no matching
    email_id ever appended returns None cleanly.

The display path (`PhishingDetectionApp._upload_results`) is intentionally
NOT touched by this module — see ADR §"Why this split".
"""
from __future__ import annotations

import json
import logging
import os
import threading
from pathlib import Path
from typing import Optional, Union

logger = logging.getLogger(__name__)


class EmailLookupIndex:
    """
    Thread-safe email_id -> JSONL-offset index.

    Constructed once per process; passed to the upload handler and the
    feedback endpoint via dependency injection. Owns no file handles
    between calls — it `open()`s for each lookup so concurrent writers
    don't fight a long-lived handle.
    """

    def __init__(self, jsonl_path: Union[str, Path] = "data/results.jsonl"):
        self.jsonl_path = Path(jsonl_path)
        self._index: dict[str, int] = {}
        # (mtime_ns, size_bytes, last_indexed_offset) for stat-and-reload.
        # last_indexed_offset is where the next walk should start from
        # so we don't re-walk lines we already indexed.
        self._stat: tuple[int, int, int] = (0, 0, 0)
        self._lock = threading.RLock()
        self._build()

    # ─── Public API ─────────────────────────────────────────────────────────

    def lookup(self, email_id: str) -> Optional[dict]:
        """
        Return the parsed JSONL record for `email_id`, or None.

        On miss, performs a single stat-and-reload retry to catch the
        in-process append staleness window AND external appends from
        another writer. A second miss is a real "unknown email_id".
        """
        if not email_id:
            return None

        with self._lock:
            offset = self._index.get(email_id)
            if offset is not None:
                record = self._read_at(offset)
                if record is not None and record.get("email_id") == email_id:
                    return record
                # Offset stale (file was rewritten / truncated under us).
                # Force a full rebuild and retry below.
                logger.debug(
                    "Index offset for %s pointed at a different record; rebuilding",
                    email_id,
                )
                self._build()
                offset = self._index.get(email_id)
                if offset is not None:
                    record = self._read_at(offset)
                    if record is not None and record.get("email_id") == email_id:
                        return record
                return None

            # Miss. Try a stat-and-reload before declaring "unknown".
            if self._stat_changed():
                self._catch_up_tail()
                offset = self._index.get(email_id)
                if offset is not None:
                    record = self._read_at(offset)
                    if record is not None and record.get("email_id") == email_id:
                        return record

        return None

    def add(self, email_id: str, line_offset: int) -> None:
        """
        Record the byte offset of a freshly-appended JSONL line.

        The caller is responsible for the actual file write. The pattern
        in the upload handler is:

            with open(jsonl_path, "a") as f:
                offset = f.tell()        # offset of the line we are about to write
                f.write(record_json + "\\n")
            index.add(email_id, offset)

        `add` does NOT do I/O. It updates the in-memory dict and the
        cached stat tuple so a subsequent lookup doesn't trip the
        stat-and-reload retry unnecessarily.
        """
        if not email_id:
            return
        with self._lock:
            self._index[email_id] = line_offset
            # Refresh the cached stat so the next lookup sees this append
            # as "no change" and skips the catch-up walk.
            self._refresh_stat_unlocked()

    def invalidate(self) -> None:
        """
        Clear the index and force a rebuild on the next lookup.

        Called by `src/automation/retention.py::purge_results_jsonl`
        after the atomic swap rewrites the JSONL — every offset in the
        old index is invalid against the new file.
        """
        with self._lock:
            self._index.clear()
            self._stat = (0, 0, 0)
            self._build()

    def __len__(self) -> int:
        with self._lock:
            return len(self._index)

    def __contains__(self, email_id: str) -> bool:
        return self.lookup(email_id) is not None

    # ─── Internals ──────────────────────────────────────────────────────────

    def _build(self) -> None:
        """Walk the entire JSONL and build the index from scratch."""
        with self._lock:
            self._index.clear()
            if not self.jsonl_path.exists():
                self._stat = (0, 0, 0)
                return
            self._walk_from(0)
            self._refresh_stat_unlocked()
            logger.info(
                "EmailLookupIndex built from %s: %d entries",
                self.jsonl_path, len(self._index),
            )

    def _catch_up_tail(self) -> None:
        """
        Walk only the new bytes appended since the last refresh.

        Used by `lookup` after a stat-changed miss. If the file was
        truncated (size shrank), fall back to a full rebuild.
        """
        with self._lock:
            if not self.jsonl_path.exists():
                self._index.clear()
                self._stat = (0, 0, 0)
                return
            current_size = self.jsonl_path.stat().st_size
            last_size = self._stat[1]
            last_offset = self._stat[2]
            if current_size < last_size:
                # File shrank — was rewritten or truncated. Full rebuild.
                logger.debug("results.jsonl shrank; full index rebuild")
                self._build()
                return
            self._walk_from(last_offset)
            self._refresh_stat_unlocked()

    def _walk_from(self, start_offset: int) -> None:
        """
        Index every valid JSON line from `start_offset` to EOF.

        Lines that fail to parse are skipped silently — the FM2 mitigation
        from the ADR (truncated final line at a partial-write crash, or
        a manual edit that introduced garbage).
        """
        try:
            with self.jsonl_path.open("rb") as fh:
                fh.seek(start_offset)
                while True:
                    offset = fh.tell()
                    raw = fh.readline()
                    if not raw:
                        break
                    line = raw.rstrip(b"\n").rstrip(b"\r")
                    if not line.strip():
                        continue
                    try:
                        record = json.loads(line.decode("utf-8"))
                    except (json.JSONDecodeError, UnicodeDecodeError):
                        # FM2: partial-write crash, garbage line, etc.
                        continue
                    eid = record.get("email_id")
                    if isinstance(eid, str) and eid:
                        self._index[eid] = offset
        except OSError as e:
            logger.warning("Failed to walk %s: %s", self.jsonl_path, e)

    def _read_at(self, offset: int) -> Optional[dict]:
        """Read one JSON record at the given byte offset. None on failure."""
        try:
            with self.jsonl_path.open("rb") as fh:
                fh.seek(offset)
                raw = fh.readline()
                if not raw:
                    return None
                line = raw.rstrip(b"\n").rstrip(b"\r")
                if not line.strip():
                    return None
                return json.loads(line.decode("utf-8"))
        except (OSError, json.JSONDecodeError, UnicodeDecodeError):
            return None

    def _stat_changed(self) -> bool:
        """True if the file's (mtime, size) differs from the cached tuple."""
        if not self.jsonl_path.exists():
            return self._stat != (0, 0, 0)
        st = self.jsonl_path.stat()
        return (st.st_mtime_ns, st.st_size) != (self._stat[0], self._stat[1])

    def _refresh_stat_unlocked(self) -> None:
        """Update the cached stat tuple to current file state."""
        if not self.jsonl_path.exists():
            self._stat = (0, 0, 0)
            return
        st = self.jsonl_path.stat()
        self._stat = (st.st_mtime_ns, st.st_size, st.st_size)
