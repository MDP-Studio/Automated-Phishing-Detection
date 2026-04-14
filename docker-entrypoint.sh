#!/usr/bin/env bash
#
# Docker entrypoint for the phishing-detection orchestrator.
#
# Runs as root for one job: chown the bind-mounted data and log
# directories to the runtime UID so the non-root `phishing` user can
# write to them. On Linux hosts, bind mounts inherit the host UID/GID
# of the source path (typically root or the host user, NEITHER of which
# matches the in-container `phishing` UID 1000). Without this script,
# the container would silently fail to write `data/results.jsonl`,
# `data/feedback.db`, and the log files — exactly the breakage the
# audit's #19 finding called out.
#
# After fixing ownership, `gosu` drops privileges and exec's the
# command. There is intentionally no shell loop, no signal indirection,
# and no PID 1 trickery — gosu exec replaces the shell so the container
# receives signals correctly.
#
# Bypass: set ENTRYPOINT_SKIP_CHOWN=1 to skip the chown step (useful
# for development containers where the bind mounts are already owned
# correctly, e.g. when running rootless Docker or on Docker Desktop
# for Mac/Windows where ownership is virtualised).

set -euo pipefail

APP_UID="${APP_UID:-1000}"
APP_GID="${APP_GID:-1000}"
APP_USER="phishing"

# Ensure the directories exist (idempotent) — bind mounts may have been
# created empty, or may not exist at all on the first run.
mkdir -p /app/data /app/logs

if [ "${ENTRYPOINT_SKIP_CHOWN:-0}" = "0" ]; then
    # Only chown if we are actually root. If the caller already runs the
    # container as a non-root user (e.g. `docker run --user`), we cannot
    # chown anyway and trying would emit confusing error messages.
    if [ "$(id -u)" = "0" ]; then
        chown -R "${APP_UID}:${APP_GID}" /app/data /app/logs 2>/dev/null || {
            echo "[entrypoint] WARNING: could not chown /app/data or /app/logs." >&2
            echo "[entrypoint] If you see permission errors writing results.jsonl," >&2
            echo "[entrypoint] manually chown the host bind-mount source directories" >&2
            echo "[entrypoint] to UID ${APP_UID} or set ENTRYPOINT_SKIP_CHOWN=1." >&2
        }
    fi
fi

# Drop privileges and exec the command. If we are already non-root,
# skip gosu entirely.
if [ "$(id -u)" = "0" ]; then
    exec gosu "${APP_USER}" "$@"
else
    exec "$@"
fi
