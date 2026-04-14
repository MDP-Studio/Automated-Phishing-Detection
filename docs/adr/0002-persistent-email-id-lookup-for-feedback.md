# ADR 0002 — Persistent email_id lookup for analyst feedback

- **Status:** accepted
- **Date:** 2026-04-15
- **Cycle:** 8 (audit item #9 from the cycle 2 review)
- **Supersedes:** none
- **Superseded by:** none

## Context

`PhishingDetectionApp._upload_results` is an in-memory list capped at 200 entries (`main.py:319-321`). It serves two purposes today:

1. **Display:** the monitor page renders the most recent uploads via `monitor_recent + list(self._upload_results[-50:])` (`main.py:563`).
2. **Lookup:** three endpoints resolve `email_id → sender` for downstream actions:
   - `/api/monitor/email/{email_id}` — display the full record for one email (`main.py:598-603`).
   - `/api/feedback` false-negative path — look up sender to add to local blocklist (`main.py:845-863`).
   - `/api/feedback` false-positive path — look up sender to add to local allowlist (`main.py:865-884`).

All three lookups walk `_upload_results` in reverse and silently no-op (`sender = ""`) when the `email_id` is not in the in-memory list. **The list is wiped on restart and roll-deletes entries past 200**, so a perfectly normal sequence of events — analyst uploads an email at 09:00, restarts the server at lunch, submits feedback at 14:00 — produces a silent feedback failure where the blocklist mutation never happens. The endpoint returns 200 with `actions_taken: []` and the analyst has no way to tell the action was lost.

This is audit item #9 from the cycle 2 review. The cycle 7 reviewer flagged it as a P1 worth fixing in its own dedicated cycle with an ADR first.

## Decision

**Split the problem along the display-vs-lookup axis.** The display path keeps `_upload_results` exactly as-is: in-memory, capped at 200, wiped on restart. The lookup path moves to a persistent index over `data/results.jsonl`, which is already the source of truth for analysis history (`main.py:323-329` writes to it on every upload).

For the lookup path, build an **in-memory `email_id → byte_offset` index** at startup by walking `results.jsonl` once. Update on every append. Lookups seek to the offset and read one line.

### Why this split

The two purposes have different requirements that the cycle 7 reviewer made explicit:

| Property | Display | Lookup |
|---|---|---|
| Latency target | sub-100ms render | analyst-action latency, hundreds of ms is fine |
| Capacity | "last 50 visible" | "any email since project start" |
| Persistence required | no | **yes** |
| Hot-path | yes (monitor refresh) | no (one call per feedback submit) |
| Failure mode if data missing | empty monitor page | **silent feedback no-op** |

Conflating these into one storage decision is what produced the current bug — `_upload_results` was the right shape for display and got accidentally borrowed for lookup. Splitting them means each path picks the right tool: in-memory list for display, indexed persistent log for lookup.

## Options considered

### (a) Extend the SQLAlchemy feedback DB schema

Add an `analyzed_email` table indexed by `email_id` with sender, timestamp, verdict, score. Upload handler INSERTs on every analysis; feedback endpoint SELECTs.

**Pros:** transactional, query-by-time-range falls out for free, no index-staleness window.
**Cons:** the feedback DB is currently the system of record for *analyst decisions only*. Mixing analysis history into it muddies the schema, expands the migration surface area, and adds a write to every upload. Also doubles the things `purge` has to clean up.

### (b) Sidecar JSONL appended on every upload

Write `data/upload_index.jsonl` alongside `data/results.jsonl`, with one record per upload containing `{email_id, sender, timestamp}`.

**Rejected.** This pattern-matches as "small focused storage for the lookup case" but it is **pure duplication of `data/results.jsonl`**. The main JSONL is already written on every upload (`main.py:328`), it already contains the email_id and sender, and it is already the file that `purge` operates on. Adding a second log creates two append paths that can drift, two files to retain, two files to query, and zero new capability. Including this option in the ADR explicitly so the obvious-but-wrong pattern-match is closed off rather than re-proposed in a future cycle.

### (c) In-memory `email_id → offset` index over `data/results.jsonl` *(adopted)*

Walk `results.jsonl` once at startup, building `dict[email_id, int]` mapping each id to the byte offset of its line. On lookup, `f.seek(offset); f.readline(); json.loads(...)`. On append, `tell()` before write to capture the offset of the new line.

**Pros:** zero duplication, the index is reconstructible from any state of the JSONL (no migration ever required), memory is bounded by *number of entries* not record size, lookups are O(1) hash plus one disk seek which is cheap on any modern filesystem. Piggybacks on the existing JSONL writes that already happen — adding the index is a single in-memory dict update, not a second I/O.

**Cons:** index goes stale during the millisecond between an append-to-JSONL and the in-memory dict update. The lookup tolerates this with a single retry-with-rebuild on miss (see "Failure modes" below). On corrupted JSONL (truncated last line, write crash mid-flight), the index entry for the bad line is dropped at rebuild and the lookup returns "unknown email_id" cleanly.

### Why not the within-(c) variations the reviewer mentioned

The cycle 7 review identified three sub-options inside (c):

1. **Linear scan every lookup** — rejected. O(n) per lookup degrades silently as `results.jsonl` grows. The whole point of an index is to not do this.
2. **In-memory offset index, rebuilt on restart** — *adopted, this is what the ADR specifies.*
3. **Sidecar SQLite index** — over-engineering at portfolio scale. Adoptable later if the index becomes hot enough that startup-walk is too slow, but for 74 entries today (and projected low-thousands by the time the project is interview material) it's not warranted.

## Decision criteria recap

| Criterion | (a) DB schema | (b) sidecar JSONL | (c) in-mem offset index |
|---|---|---|---|
| Implementation cost | medium (schema + migration) | low (just append) | low (~150 lines) |
| Survives restart | yes | yes | **yes** (rebuild on init) |
| No duplication of existing log | yes | **no** | **yes** |
| Retention-purge interaction | one extra purge target | two purge targets | **piggyback on existing purge** |
| Concurrent write tolerance | DB ACID | append-atomicity | **append + retry-on-miss** |
| Test surface area | medium | medium | low |
| Memory cost | DB cache | none in-process | small (entries × ~80 bytes) |
| Risk if scale hits production levels | none | none | switch to (3) sidecar SQLite later |

(c) wins on five of eight rows, ties on the rest, and has the cleanest upgrade path if scale ever becomes a problem.

## Failure modes

### FM1 — Index staleness window

**Risk:** an upload completes, the JSONL append hits the disk, but the in-memory index hasn't been updated yet (e.g. the append succeeded and the next line of code raised). A lookup in that window misses the new entry.

**Mitigation:**
1. The upload handler updates the index *immediately after* the append, in the same try block, with no other I/O between them. The window is bounded by a single Python statement.
2. On lookup miss, the index does a **stat-and-reload** retry: if the JSONL's `mtime` or size has changed since the index was built or last refreshed, the index walks new tail entries appended since then and re-tries the lookup once. This catches both the staleness window *and* the case where another process appended to the file (e.g. monitor + dashboard sharing a JSONL).
3. Retry happens at most once per lookup. A second miss after rebuild is a real "unknown email_id" and returns a clean error.

The chosen latency semantic, written here for durability: **lookups are eventually consistent within one rebuild cycle (typically milliseconds). A lookup that misses immediately after a successful append will succeed on retry. A lookup with no matching email_id ever appended returns `None` cleanly.**

### FM2 — Partial-write crash

**Risk:** the server crashes mid-line during an append. The JSONL has a truncated final line; the index entry was never recorded.

**Mitigation:** the rebuild walker treats any line that fails `json.loads` as "skipped, not indexed". The truncated entry is invisible to lookups, which is exactly the right behaviour — the analysis it represented is lost, and the lookup returns "unknown email_id" cleanly so the feedback endpoint returns an explicit error rather than a silent no-op. A scheduled recovery sweep that truncates the file at the last valid newline is a future improvement, tracked in ROADMAP.

### FM3 — Retention purge interaction

**Risk:** `python main.py purge --older-than 30` rewrites `results.jsonl` via the cycle 5 atomic-swap. After the swap, every offset in the in-memory index is invalid (the new file has different offsets) and the email_ids that were dropped are still in the dict pointing at random byte positions. Lookups would seek into the wrong line.

**Mitigation:** `purge_results_jsonl` accepts an optional `EmailLookupIndex` and calls `index.invalidate()` after the atomic swap, forcing a rebuild on the next lookup. The `main.py purge` subcommand passes the app's index. Standalone usage of `purge_results_jsonl` (no index supplied) still works correctly; the index just has to be rebuilt on the next startup.

### FM4 — Concurrent writers

**Risk:** another process (a separate worker, a monitor running in parallel) appends to `results.jsonl` while the dashboard is up. The dashboard's index is stale until the next restart.

**Mitigation:** the same stat-and-reload mechanism from FM1 also catches external appends. On lookup miss, the index checks the file's `(mtime, size)` against its last-known tuple; if they differ, it walks from the last-known offset to EOF and indexes the new entries. This means cross-process append visibility is *eventually consistent within one missed lookup*, which is acceptable for the analyst-action use case.

A stricter "all writers go through the index" guarantee would require file locks (`fcntl.flock`) which adds platform-specific complexity. Defer until there's evidence cross-process writes are common.

### FM5 — Index memory growth

**Risk:** as `results.jsonl` accumulates entries over months, the index grows unboundedly.

**Mitigation:** the cycle 5 retention purge already runs on a 30-day window by default. After purge, the index is rebuilt from the trimmed file. Memory growth is bounded by retention × upload rate. At portfolio scale (a few hundred uploads per month) this stays under a megabyte indefinitely. If production scale ever requires tighter bounds, switch to sub-option 3 (sidecar SQLite) per the ROADMAP.

## Test strategy

The smoking-gun test that should have caught the bug if it had existed before:

```
test_blocklist_mutation_succeeds_on_pre_restart_email
  - Write a record to results.jsonl
  - Construct an EmailLookupIndex (simulating restart — no in-memory state)
  - Look up the record by email_id
  - Assert the sender is returned
```

Cross-cycle ramifications also tested:

- **Unknown email_id returns None cleanly** — feedback endpoint handles this without a silent no-op
- **Append updates the index** without re-walking the file
- **Stat-and-reload catches a write that bypassed the in-process append** path
- **Retention purge invalidates the index** and the next lookup rebuilds correctly
- **Truncated final line** (partial-write crash simulation) is skipped by the rebuild walker
- **Index memory** stays bounded by entry count, not file size — verified via a synthetic 1000-entry test

## Migration

**No migration script needed.** Existing `data/results.jsonl` files from prior runs of the project are valid input to the new index — the rebuild walker reads them at startup the same way it'd read a freshly-created file. Operators upgrading to the cycle 8 build see the index built from their existing log on first launch with zero action required. This is called out in the cycle 8 commit message so future-me doesn't wonder why there's no migration.

## Consequences

**Positive:**
- Closes a silent-data-loss class bug. The feedback endpoint now produces a deterministic outcome whether or not the email survived the in-memory cap.
- Display path stays simple — `_upload_results` is preserved for what it was always good at.
- Index is reconstructible from any state of `results.jsonl`. There is no separate piece of state to back up, migrate, or purge.
- The retention purge integration means cycle 5 and cycle 8 don't fight each other.

**Negative:**
- Adds a startup walk over `results.jsonl`. At current scale this is milliseconds; needs revisiting if uploads ever reach hundreds of thousands.
- Introduces an "eventually consistent within one rebuild" semantic that needs to be documented in code so a future maintainer doesn't accidentally tighten it (which would require file locks).

**Neutral:**
- Backward compatibility: any existing `results.jsonl` works as input. No format changes.
- The `_upload_results` list is unchanged in shape and behaviour.

## Open questions

- **Should the index also support time-range queries?** Useful for the eval harness, possibly worth adding when the eval harness lands. Not required for the feedback fix and not implemented in cycle 8.
- **Should the index live in `src/feedback/` or `src/automation/`?** Goes in `src/feedback/` because it exists to serve the feedback endpoint's lookup path. Other consumers (monitor email detail) are coincidental users.
- **Should there be an HTTP endpoint to inspect index state for debugging?** Probably yes long-term but out of scope for cycle 8. A `print()` from a Python REPL is enough for now.
