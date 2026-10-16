"""Holehe integration — 120+ sites via register / forgot-password endpoints."""

from __future__ import annotations

import asyncio
import time
from typing import List, Tuple

import httpx

from ..core.result import ClaimStatus, SourceSummary, UnifiedResult


async def scan(target: str, target_type: str, cfg) -> Tuple[List[UnifiedResult], SourceSummary]:
    summary = SourceSummary(name="holehe")
    if target_type != "email":
        summary.available = False
        summary.note = "email-only source"
        return [], summary

    start = time.time()
    try:
        from holehe.core import get_functions, import_submodules
    except Exception as e:
        summary.available = False
        summary.note = f"import failed: {e}"
        return [], summary

    try:
        modules = import_submodules("holehe.modules")
        websites = get_functions(modules)
    except Exception as e:
        summary.available = False
        summary.note = f"module load failed: {e}"
        return [], summary

    if cfg.sites:
        from ..core.normalize import site_match
        websites = [w for w in websites if site_match(w.__name__, "", cfg.sites)]

    sem = asyncio.Semaphore(cfg.max_concurrent)
    out: List[UnifiedResult] = []

    async with httpx.AsyncClient(timeout=cfg.timeout) as client:
        async def run_one(fn):
            async with sem:
                bucket: list = []
                try:
                    await fn(target, client, bucket)
                except Exception:
                    return None
                return bucket[0] if bucket else None

        tasks = [run_one(fn) for fn in websites]
        for coro in asyncio.as_completed(tasks):
            item = await coro
            summary.checked += 1
            if item is None:
                summary.errors += 1
                continue
            if item.get("rateLimit"):
                summary.errors += 1
                continue
            if not item.get("exists"):
                continue

            summary.found += 1
            extra = {}
            if item.get("emailrecovery"):
                extra["recovery_hint"] = str(item["emailrecovery"])
            if item.get("phoneNumber"):
                extra["phone_hint"] = str(item["phoneNumber"])
            if item.get("others"):
                extra["details"] = str(item["others"])[:300]
            if item.get("method"):
                extra["method"] = str(item["method"])

            out.append(
                UnifiedResult(
                    target=target,
                    target_type=target_type,
                    source="holehe",
                    site=str(item.get("name", "")).capitalize(),
                    url=f"https://{item.get('domain', '')}",
                    status=ClaimStatus.EXISTS,
                    confidence=0.85,
                    method=str(item.get("method") or "forgot_password_endpoint"),
                    extra=extra,
                )
            )

    summary.seconds = time.time() - start
    return out, summary
