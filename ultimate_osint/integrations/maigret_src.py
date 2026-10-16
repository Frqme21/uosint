"""Maigret integration — 3000+ site username database via its native library."""

from __future__ import annotations

import asyncio
import logging
import time
from importlib import resources
from typing import Dict, List, Tuple

from ..core.result import ClaimStatus, SourceSummary, UnifiedResult

_db_cache = None


def _load_sites(top: int):
    global _db_cache
    from maigret import MaigretDatabase

    if _db_cache is None:
        db_path = resources.files("maigret") / "resources" / "data.json"
        _db_cache = MaigretDatabase().load_from_path(str(db_path))

    if top and top > 0:
        return _db_cache.ranked_sites_dict(top=top, disabled=False)
    return _db_cache.ranked_sites_dict(disabled=False)


async def scan(target: str, target_type: str, cfg) -> Tuple[List[UnifiedResult], SourceSummary]:
    summary = SourceSummary(name="maigret")
    if target_type == "email":
        summary.available = False
        summary.note = "username-only source"
        return [], summary

    start = time.time()
    try:
        from maigret import search as maigret_search
        from maigret.result import MaigretCheckStatus
    except Exception as e:
        summary.available = False
        summary.note = f"import failed: {e}"
        return [], summary

    top = 0 if cfg.deep else cfg.top_maigret
    try:
        sites = await asyncio.to_thread(_load_sites, top)
    except Exception as e:
        summary.available = False
        summary.note = f"db load failed: {e}"
        return [], summary

    if cfg.sites:
        from ..core.normalize import site_match
        sites = {name: s for name, s in sites.items() if site_match(name, "", cfg.sites)}

    logger = logging.getLogger("uosint.maigret")
    logger.handlers.clear()
    logger.addHandler(logging.NullHandler())
    logger.setLevel(logging.CRITICAL)

    try:
        res = await maigret_search(
            username=target,
            site_dict=dict(sites),
            logger=logger,
            timeout=cfg.timeout,
            id_type="username",
            max_connections=cfg.max_concurrent,
            no_progressbar=True,
            is_parsing_enabled=not cfg.fast,
            forced=False,
            retries=0,
        )
    except Exception as e:
        summary.available = False
        summary.note = f"scan failed: {e}"
        summary.seconds = time.time() - start
        return [], summary

    out: List[UnifiedResult] = []
    for site_name, site_result in res.items():
        summary.checked += 1
        check = site_result.get("status")
        if check is None:
            summary.errors += 1
            continue

        st_map = {
            MaigretCheckStatus.CLAIMED: ClaimStatus.EXISTS,
            MaigretCheckStatus.AVAILABLE: ClaimStatus.NOT_EXISTS,
            MaigretCheckStatus.ILLEGAL: ClaimStatus.SKIPPED,
            MaigretCheckStatus.UNKNOWN: ClaimStatus.UNKNOWN,
        }
        st = st_map.get(check.status, ClaimStatus.UNKNOWN)
        if st == ClaimStatus.EXISTS:
            summary.found += 1
        elif st == ClaimStatus.UNKNOWN:
            summary.errors += 1
        elif st == ClaimStatus.SKIPPED:
            summary.skipped += 1
        else:
            continue  # not found -> stats only

        url = site_result.get("url_user") or ""
        extra = {}
        context = getattr(check, "context", None)
        if context:
            extra["context"] = str(context)
        ids_usernames = site_result.get("ids_usernames") or {}
        if ids_usernames:
            extra["linked_ids"] = ", ".join(f"{k}={v}" for k, v in list(ids_usernames.items())[:6])
        ids_links = site_result.get("ids_links") or []
        if ids_links:
            extra["linked_profiles"] = ", ".join(ids_links[:4])
        http_status = site_result.get("http_status")
        if isinstance(http_status, int):
            extra["http_status"] = http_status

        out.append(
            UnifiedResult(
                target=target,
                target_type=target_type,
                source="maigret",
                site=site_name,
                url=url,
                status=st,
                confidence=0.75,
                method="page_heuristics",
                extra=extra,
            )
        )

    summary.seconds = time.time() - start
    return out, summary
