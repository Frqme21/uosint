"""Socialscan integration — signup-API availability checks (100% query accuracy)."""

from __future__ import annotations

import asyncio
import time
from typing import List, Tuple

from ..core.result import ClaimStatus, SourceSummary, UnifiedResult


async def scan(target: str, target_type: str, cfg) -> Tuple[List[UnifiedResult], SourceSummary]:
    summary = SourceSummary(name="socialscan")
    start = time.time()

    try:
        import aiohttp
        from socialscan.platforms import Platforms, PrerequestRequired
        from socialscan.util import init_checkers, init_prerequest, query
    except Exception as e:
        summary.available = False
        summary.note = f"import failed: {e}"
        return [], summary

    platforms = list(Platforms)
    if cfg.no_nsfw:
        platforms = [p for p in platforms if "porn" not in p.name.lower() and "xxx" not in p.name.lower()]
    if cfg.sites:
        from ..core.normalize import site_match
        platforms = [p for p in platforms if site_match(p.name, "", cfg.sites)]

    try:
        session = aiohttp.ClientSession()
        try:
            checkers = init_checkers(session, platforms)
            # platforms needing a token prefetch (GitHub, Instagram, ...)
            for platform in platforms:
                if issubclass(platform.value, PrerequestRequired):
                    try:
                        await init_prerequest(platform, checkers)
                    except Exception:
                        pass
            results = await asyncio.gather(
                *[query(target, p, checkers) for p in platforms], return_exceptions=True
            )
        finally:
            await session.close()
    except Exception as e:
        summary.available = False
        summary.note = f"scan failed: {e}"
        summary.seconds = time.time() - start
        return [], summary

    out: List[UnifiedResult] = []
    for resp in results:
        if resp is None or isinstance(resp, BaseException):
            summary.checked += 1
            summary.errors += 1
            continue
        summary.checked += 1
        if not resp.success:
            summary.errors += 1
            continue
        if not resp.valid:
            summary.skipped += 1
            continue
        # available=False + success = the identifier is REGISTERED / in use
        if resp.available:
            continue  # free for registration -> not a finding
        summary.found += 1
        link = resp.link or ""
        if link and "{}" in link:
            try:
                link = link.format(target)
            except Exception:
                link = ""
        site_name = getattr(resp.platform.value, "__name__", None) or resp.platform.name
        out.append(
            UnifiedResult(
                target=target,
                target_type=target_type,
                source="socialscan",
                site=site_name,
                url=link or f"https://{resp.platform.name.lower()}",
                status=ClaimStatus.EXISTS,
                confidence=0.95,
                method="signup_api",
                extra={"platform": resp.platform.name},
            )
        )

    summary.seconds = time.time() - start
    return out, summary
