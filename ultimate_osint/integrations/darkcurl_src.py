"""DarkCurl integration — 295+ username/email modules with rich metadata extraction."""

from __future__ import annotations

import asyncio
import time
from typing import List, Tuple

from ..core.normalize import site_key, site_match
from ..core.result import ClaimStatus, SourceSummary, UnifiedResult


def _run_darkcurl(target: str, is_email: bool, allow_loud: bool, no_nsfw: bool, only_found: bool):
    """Blocking bridge into DarkCurl (it manages its own event loop)."""
    from darkcurl.core.helpers import ScanConfig
    from darkcurl.core.orchestrator import run_user_full
    from darkcurl.core.email_orchestrator import run_email_full_batch

    config = ScanConfig(
        allow_loud=allow_loud,
        no_nsfw=no_nsfw,
        only_found=only_found,
        verbose=False,
    )
    if is_email:
        return run_email_full_batch(target, config)
    return run_user_full(target, config)


async def scan(target: str, target_type: str, cfg) -> Tuple[List[UnifiedResult], SourceSummary]:
    start = time.time()
    summary = SourceSummary(name="darkcurl")
    is_email = target_type == "email"

    try:
        results = await asyncio.to_thread(
            _run_darkcurl,
            target,
            is_email,
            cfg.allow_loud,
            cfg.no_nsfw,
            not cfg.verbose,
        )
    except Exception as e:  # darkcurl blew up entirely
        summary.available = False
        summary.note = f"failed: {e}"
        summary.seconds = time.time() - start
        return [], summary

    out: List[UnifiedResult] = []
    status_map = {
        0: ClaimStatus.EXISTS,  # TAKEN
        1: ClaimStatus.NOT_EXISTS,  # AVAILABLE
        2: ClaimStatus.UNKNOWN,  # ERROR
        3: ClaimStatus.SKIPPED,  # SKIPPED
    }
    if cfg.sites:
        results = [r for r in results if site_match(r.site_name, r.url, cfg.sites)]
    for r in results:
        summary.checked += 1
        st = status_map.get(r.status.value, ClaimStatus.UNKNOWN)
        if st == ClaimStatus.EXISTS:
            summary.found += 1
        elif st == ClaimStatus.UNKNOWN:
            summary.errors += 1
        elif st == ClaimStatus.SKIPPED:
            summary.skipped += 1

        out.append(
            UnifiedResult(
                target=target,
                target_type=target_type,
                source="darkcurl",
                site=r.site_name or "",
                url=r.url or "",
                status=st,
                confidence=0.9 if st == ClaimStatus.EXISTS else 0.7,
                method="site_module",
                extra=dict(r.extra or {}),
                reason=str(r.get_reason() or ""),
            )
        )

    # Only "found" claims matter downstream; keep the rest for stats only.
    summary.seconds = time.time() - start
    return [r for r in out if r.status == ClaimStatus.EXISTS], summary
