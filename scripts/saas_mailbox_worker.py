#!/usr/bin/env python3
"""Run or health-check the tenant-scoped SaaS mailbox polling worker."""

from __future__ import annotations

import argparse
import asyncio
import json
import logging
import signal
import sys
from datetime import datetime, timezone
from pathlib import Path

from dotenv import load_dotenv

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))
load_dotenv(PROJECT_ROOT / ".env", override=True)

from main import PhishingDetectionApp, _api_payload_from_pipeline  # noqa: E402  # agent-quality: allow dotenv first
from src.config import PipelineConfig  # noqa: E402  # agent-quality: allow dotenv first
from src.saas.database import SaaSStore  # noqa: E402  # agent-quality: allow dotenv first
from src.saas.mailbox_scanner import scan_mailbox  # noqa: E402  # agent-quality: allow dotenv first
from src.saas.mailbox_worker import (  # noqa: E402  # agent-quality: allow dotenv first
    SaaSMailboxWorker,
    WorkerRunStats,
    run_worker_loop,
)

logger = logging.getLogger(__name__)


def _write_heartbeat(path: Path, stats: WorkerRunStats) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "status": "ok",
        "updated_at": datetime.now(timezone.utc).isoformat(),
        "stats": stats.to_dict(),
    }
    temporary = path.with_suffix(f"{path.suffix}.tmp")
    temporary.write_text(json.dumps(payload, sort_keys=True), encoding="utf-8")
    temporary.replace(path)


def _healthcheck(path: Path, *, max_age_seconds: int) -> int:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
        updated = datetime.fromisoformat(str(payload["updated_at"]).replace("Z", "+00:00"))
    except (OSError, KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
        logger.error("SaaS mailbox worker heartbeat is unavailable: %s", type(exc).__name__)
        return 1
    age = (datetime.now(timezone.utc) - updated.astimezone(timezone.utc)).total_seconds()
    if payload.get("status") != "ok" or age > max_age_seconds:
        logger.error("SaaS mailbox worker heartbeat is stale or unhealthy")
        return 1
    return 0


async def _run(config: PipelineConfig, *, once: bool) -> None:
    if not config.saas_continuous_monitoring_enabled:
        heartbeat_path = Path(config.saas_mailbox_worker_heartbeat_path)
        disabled_stats = WorkerRunStats()
        _write_heartbeat(heartbeat_path, disabled_stats)
        if once:
            return
        logger.info("Continuous mailbox monitoring is disabled by configuration")
        while True:
            await asyncio.sleep(max(1, config.saas_mailbox_worker_idle_seconds))
            _write_heartbeat(heartbeat_path, disabled_stats)
    application = PhishingDetectionApp()
    store = SaaSStore(config.saas_db_path)

    async def scan_one(*, context, mailbox, max_results: int) -> dict:
        return await scan_mailbox(
            store=store,
            context=context,
            mailbox=mailbox,
            max_results=max_results,
            pipeline=application.pipeline,
            payload_builder=_api_payload_from_pipeline,
            api_config=application.config.api,
            operational_alerts=application.operational_alerts,
            source="mailbox_poll",
        )

    worker = SaaSMailboxWorker(
        store=store,
        scan_mailbox=scan_one,
        lease_seconds=max(
            config.saas_mailbox_worker_lease_seconds,
            (config.pipeline_timeout * config.saas_mailbox_worker_max_results) + 120,
        ),
        batch_size=config.saas_mailbox_worker_batch_size,
        max_results=config.saas_mailbox_worker_max_results,
    )
    heartbeat_path = Path(config.saas_mailbox_worker_heartbeat_path)
    if once:
        _write_heartbeat(heartbeat_path, await worker.run_once())
        return

    stop_event = asyncio.Event()
    loop = asyncio.get_running_loop()
    for signal_name in (signal.SIGTERM, signal.SIGINT):
        try:
            loop.add_signal_handler(signal_name, stop_event.set)
        except NotImplementedError:
            logger.info("Signal handlers are not available on this event loop")
    await run_worker_loop(
        worker,
        idle_seconds=config.saas_mailbox_worker_idle_seconds,
        heartbeat=lambda stats: _write_heartbeat(heartbeat_path, stats),
        stop_event=stop_event,
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--once", action="store_true")
    parser.add_argument("--healthcheck", action="store_true")
    args = parser.parse_args()
    config = PipelineConfig.from_env()
    heartbeat_path = Path(config.saas_mailbox_worker_heartbeat_path)
    if args.healthcheck:
        max_age = max(
            120,
            config.saas_mailbox_worker_idle_seconds * 4,
            config.saas_mailbox_worker_lease_seconds * 2,
        )
        return _healthcheck(heartbeat_path, max_age_seconds=max_age)
    asyncio.run(_run(config, once=args.once))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
