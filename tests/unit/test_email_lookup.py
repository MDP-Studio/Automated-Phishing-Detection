"""
Tests for src/feedback/email_lookup.py — the persistent email_id lookup
index from ADR 0002.

The smoking-gun test is `test_blocklist_mutation_succeeds_on_pre_restart_email`:
write a record to JSONL, construct a fresh index (simulating restart),
look up by email_id, assert sender comes back. If this test passes, the
silent-feedback-no-op bug from audit #9 cannot recur.
"""
from __future__ import annotations

import json
import os
import threading
from pathlib import Path

import pytest

from src.feedback.email_lookup import EmailLookupIndex


# ─── Helpers ─────────────────────────────────────────────────────────────────


def _row(email_id: str, sender: str = "x@example.com", **extra) -> str:
    record = {"email_id": email_id, "from": sender, "verdict": "CLEAN"}
    record.update(extra)
    return json.dumps(record)


def _write_jsonl(path: Path, rows: list[str]) -> None:
    path.write_text("\n".join(rows) + "\n", encoding="utf-8")


def _append_row(path: Path, line: str) -> int:
    """Append a line and return the byte offset of where it started."""
    with path.open("ab") as fh:
        offset = fh.tell()
        fh.write(line.encode("utf-8") + b"\n")
    return offset


# ─── The smoking gun ─────────────────────────────────────────────────────────


class TestSmokingGunPreRestartLookup:
    """
    The test that should have caught audit #9 if it had existed before.

    Construct a JSONL with a record, then build a *fresh* index (which
    simulates a server restart — no in-memory state from a prior process).
    The lookup must return the record by email_id. If it doesn't, the
    feedback endpoint silently no-ops on every email older than the
    in-memory cap, which is the bug.
    """

    def test_blocklist_mutation_succeeds_on_pre_restart_email(self, tmp_path):
        path = tmp_path / "results.jsonl"
        _write_jsonl(path, [
            _row("uploaded-before-restart", sender="attacker@evil.example"),
        ])

        # Simulate restart: brand new process, no in-memory _upload_results
        index = EmailLookupIndex(jsonl_path=path)

        record = index.lookup("uploaded-before-restart")

        assert record is not None, (
            "lookup returned None for an email_id present in results.jsonl. "
            "This is the audit #9 bug — feedback endpoint will silently "
            "no-op the blocklist mutation."
        )
        assert record["from"] == "attacker@evil.example"
        assert record["email_id"] == "uploaded-before-restart"


# ─── Empty / missing input ──────────────────────────────────────────────────


class TestEmptyAndMissing:
    def test_missing_file_init_does_not_crash(self, tmp_path):
        path = tmp_path / "does-not-exist.jsonl"
        index = EmailLookupIndex(jsonl_path=path)
        assert len(index) == 0
        assert index.lookup("anything") is None

    def test_empty_file_init(self, tmp_path):
        path = tmp_path / "empty.jsonl"
        path.write_text("", encoding="utf-8")
        index = EmailLookupIndex(jsonl_path=path)
        assert len(index) == 0

    def test_lookup_unknown_email_id_returns_none(self, tmp_path):
        path = tmp_path / "results.jsonl"
        _write_jsonl(path, [_row("known-1"), _row("known-2")])
        index = EmailLookupIndex(jsonl_path=path)
        assert index.lookup("never-existed") is None

    def test_empty_email_id_returns_none(self, tmp_path):
        path = tmp_path / "results.jsonl"
        _write_jsonl(path, [_row("known")])
        index = EmailLookupIndex(jsonl_path=path)
        assert index.lookup("") is None
        assert index.lookup(None) is None  # type: ignore[arg-type]


# ─── Append updates the index ───────────────────────────────────────────────


class TestAppend:
    def test_add_makes_lookup_succeed(self, tmp_path):
        path = tmp_path / "results.jsonl"
        path.touch()
        index = EmailLookupIndex(jsonl_path=path)
        assert len(index) == 0

        # Caller writes the line, then notifies the index of the offset
        line = _row("new-1", sender="alice@example.com")
        offset = _append_row(path, line)
        index.add("new-1", offset)

        assert index.lookup("new-1")["from"] == "alice@example.com"
        assert len(index) == 1

    def test_add_does_not_re_walk_existing_entries(self, tmp_path):
        """`add` must be O(1) and not re-walk the file."""
        path = tmp_path / "results.jsonl"
        # Pre-populate with 50 entries
        rows = [_row(f"id-{i}") for i in range(50)]
        _write_jsonl(path, rows)
        index = EmailLookupIndex(jsonl_path=path)
        assert len(index) == 50

        # Now append one and notify
        line = _row("id-50")
        offset = _append_row(path, line)
        index.add("id-50", offset)

        assert len(index) == 51
        # All 50 originals still resolve correctly
        for i in (0, 25, 49):
            assert index.lookup(f"id-{i}") is not None


# ─── Stat-and-reload (FM1 + FM4) ─────────────────────────────────────────────


class TestStatAndReload:
    def test_external_append_caught_on_lookup_miss(self, tmp_path):
        """
        Simulate another process appending: the in-memory index doesn't
        know about it (no `add` call). On lookup miss, stat-and-reload
        catches the new entries.
        """
        path = tmp_path / "results.jsonl"
        _write_jsonl(path, [_row("orig")])
        index = EmailLookupIndex(jsonl_path=path)
        assert index.lookup("orig") is not None

        # External writer appends, bypassing the index.add path
        # Bump mtime by a fraction of a second to ensure it differs from
        # the cached tuple even on filesystems with low time resolution.
        _append_row(path, _row("external"))
        try:
            new_mtime = path.stat().st_mtime + 1.0
            os.utime(path, (new_mtime, new_mtime))
        except OSError:
            pass

        # Lookup the externally-added entry — should rebuild and find it
        result = index.lookup("external")
        assert result is not None
        assert result["email_id"] == "external"

    def test_lookup_after_index_invalidated_rebuilds(self, tmp_path):
        path = tmp_path / "results.jsonl"
        _write_jsonl(path, [_row("a"), _row("b")])
        index = EmailLookupIndex(jsonl_path=path)

        index.invalidate()
        # After invalidate, the index must still find existing entries
        assert index.lookup("a") is not None
        assert index.lookup("b") is not None


# ─── Partial-write tolerance (FM2) ──────────────────────────────────────────


class TestPartialWriteTolerance:
    def test_truncated_final_line_is_skipped(self, tmp_path):
        """
        A partial-write crash leaves the JSONL with a truncated final
        line (no newline, no closing brace). The walker must skip it
        rather than raising or polluting the index.
        """
        path = tmp_path / "results.jsonl"
        good_line = _row("good")
        bad_line = '{"email_id": "bad", "from": "x@example'  # no closing
        path.write_text(good_line + "\n" + bad_line, encoding="utf-8")

        index = EmailLookupIndex(jsonl_path=path)

        assert index.lookup("good") is not None
        assert index.lookup("bad") is None  # truncated, not indexed

    def test_blank_lines_skipped(self, tmp_path):
        path = tmp_path / "results.jsonl"
        path.write_text(
            _row("first") + "\n\n\n" + _row("second") + "\n",
            encoding="utf-8",
        )
        index = EmailLookupIndex(jsonl_path=path)
        assert len(index) == 2

    def test_garbage_line_in_middle_skipped_others_kept(self, tmp_path):
        path = tmp_path / "results.jsonl"
        path.write_text(
            _row("a") + "\n" + "garbage not json" + "\n" + _row("b") + "\n",
            encoding="utf-8",
        )
        index = EmailLookupIndex(jsonl_path=path)
        assert index.lookup("a") is not None
        assert index.lookup("b") is not None


# ─── Retention purge interaction (FM3) ──────────────────────────────────────


class TestRetentionPurgeInteraction:
    def test_invalidate_after_purge_rebuilds_correctly(self, tmp_path):
        """
        After `purge_results_jsonl` rewrites the file with fewer rows,
        every offset in the index is invalid. Calling `invalidate()`
        must produce a correct index of the *remaining* rows.
        """
        from datetime import datetime, timedelta, timezone

        path = tmp_path / "results.jsonl"
        now = datetime(2026, 4, 14, tzinfo=timezone.utc)
        rows = [
            json.dumps({
                "email_id": "old",
                "from": "old@example.com",
                "timestamp": (now - timedelta(days=60)).isoformat(),
            }),
            json.dumps({
                "email_id": "new",
                "from": "new@example.com",
                "timestamp": (now - timedelta(days=1)).isoformat(),
            }),
        ]
        _write_jsonl(path, rows)
        index = EmailLookupIndex(jsonl_path=path)
        assert index.lookup("old") is not None
        assert index.lookup("new") is not None

        from src.automation.retention import purge_results_jsonl
        purge_results_jsonl(path, max_age_days=30, now=now)

        # Index is stale now — it still has both ids in its dict but the
        # offsets don't correspond to the right lines after the rewrite
        index.invalidate()

        assert index.lookup("old") is None  # dropped by purge
        assert index.lookup("new") is not None  # survived

    def test_purge_with_index_argument_invalidates(self, tmp_path):
        """
        `purge_results_jsonl(..., index=index)` should call invalidate()
        after the swap so callers don't have to remember.
        """
        from datetime import datetime, timedelta, timezone
        from src.automation.retention import purge_results_jsonl

        path = tmp_path / "results.jsonl"
        now = datetime(2026, 4, 14, tzinfo=timezone.utc)
        _write_jsonl(path, [
            json.dumps({
                "email_id": "expire",
                "from": "x@example.com",
                "timestamp": (now - timedelta(days=60)).isoformat(),
            }),
            json.dumps({
                "email_id": "keep",
                "from": "y@example.com",
                "timestamp": (now - timedelta(days=1)).isoformat(),
            }),
        ])
        index = EmailLookupIndex(jsonl_path=path)

        purge_results_jsonl(path, max_age_days=30, now=now, index=index)

        assert index.lookup("expire") is None
        assert index.lookup("keep") is not None


# ─── Memory bound (FM5) ─────────────────────────────────────────────────────


class TestMemoryBound:
    def test_index_size_bounded_by_entry_count_not_record_size(self, tmp_path):
        """
        Storing 1000 entries with large body fields must not blow up
        memory because the index only keeps offsets, not record bodies.
        """
        path = tmp_path / "results.jsonl"
        large_body = "x" * 5000  # 5KB per record, 5MB file total
        with path.open("w", encoding="utf-8") as fh:
            for i in range(1000):
                fh.write(json.dumps({
                    "email_id": f"id-{i}",
                    "from": f"sender{i}@example.com",
                    "body": large_body,
                }) + "\n")

        index = EmailLookupIndex(jsonl_path=path)
        assert len(index) == 1000
        # Random spot check
        rec = index.lookup("id-500")
        assert rec is not None
        assert rec["from"] == "sender500@example.com"


# ─── Concurrent access (FM4) ────────────────────────────────────────────────


class TestConcurrentAccess:
    def test_lock_protects_concurrent_lookups_and_appends(self, tmp_path):
        """
        Mixed reader + writer threads must not crash and must not
        corrupt the index. Doesn't try to prove correctness at every
        interleaving — just that the lock prevents catastrophic races.
        """
        path = tmp_path / "results.jsonl"
        path.touch()
        index = EmailLookupIndex(jsonl_path=path)

        errors: list[Exception] = []

        def writer():
            try:
                for i in range(50):
                    line = _row(f"w-{i}", sender=f"s{i}@example.com")
                    offset = _append_row(path, line)
                    index.add(f"w-{i}", offset)
            except Exception as e:
                errors.append(e)

        def reader():
            try:
                for _ in range(100):
                    index.lookup("w-0")
                    index.lookup("w-25")
                    index.lookup("nonexistent")
            except Exception as e:
                errors.append(e)

        threads = [threading.Thread(target=writer)] + [
            threading.Thread(target=reader) for _ in range(3)
        ]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert errors == []
        assert len(index) == 50


# ─── __contains__ sanity ────────────────────────────────────────────────────


class TestContainsOperator:
    def test_contains_for_known_id(self, tmp_path):
        path = tmp_path / "results.jsonl"
        _write_jsonl(path, [_row("yes")])
        index = EmailLookupIndex(jsonl_path=path)
        assert "yes" in index

    def test_not_contains_for_unknown_id(self, tmp_path):
        path = tmp_path / "results.jsonl"
        _write_jsonl(path, [_row("yes")])
        index = EmailLookupIndex(jsonl_path=path)
        assert "no" not in index


# ─── Cross-restart end-to-end (the audit #9 contract) ───────────────────────


class TestCrossRestartContract:
    """
    The full contract from ADR 0002: build an index, write a record via
    add(), then construct a SECOND fresh index from the same file
    (simulating a process restart). The new index must find the record.

    This is the specific scenario the audit #9 bug describes: analyst
    uploads at 09:00, server restarts at lunch, feedback at 14:00.
    """

    def test_record_added_via_add_is_findable_by_fresh_index(self, tmp_path):
        path = tmp_path / "results.jsonl"
        path.touch()

        # Phase 1: original process. Index, append, add.
        original = EmailLookupIndex(jsonl_path=path)
        line = _row("morning-upload", sender="boss@target.example")
        offset = _append_row(path, line)
        original.add("morning-upload", offset)
        assert original.lookup("morning-upload") is not None

        # Phase 2: process restart. Brand new index from the same file.
        # The original index object is gone (no in-memory state).
        del original
        restarted = EmailLookupIndex(jsonl_path=path)

        result = restarted.lookup("morning-upload")
        assert result is not None, (
            "restart broke the lookup — audit #9 has regressed. The "
            "feedback endpoint will silently no-op on this email_id."
        )
        assert result["from"] == "boss@target.example"

    def test_two_hundred_uploads_all_findable_after_restart(self, tmp_path):
        """
        The 200-cap on _upload_results was the second half of the bug:
        even without restart, the 201st upload pushed the 1st out of
        the in-memory list. The persistent index has no such cap.
        """
        path = tmp_path / "results.jsonl"
        path.touch()
        original = EmailLookupIndex(jsonl_path=path)

        for i in range(250):  # Past the old 200-cap
            line = _row(f"upload-{i}", sender=f"sender-{i}@example.com")
            offset = _append_row(path, line)
            original.add(f"upload-{i}", offset)

        # Simulate restart
        restarted = EmailLookupIndex(jsonl_path=path)

        # Both the OLDEST and the most recent must be findable.
        # Under the old bug, upload-0 would have been pushed off
        # _upload_results at upload-200 and the lookup would no-op.
        oldest = restarted.lookup("upload-0")
        newest = restarted.lookup("upload-249")
        assert oldest is not None
        assert oldest["from"] == "sender-0@example.com"
        assert newest is not None
        assert newest["from"] == "sender-249@example.com"
