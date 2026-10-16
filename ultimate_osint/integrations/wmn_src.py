"""WhatsMyName integration — community-maintained site database (CC BY-SA 4.0)."""

from __future__ import annotations

import asyncio
import json
import time
from pathlib import Path
from typing import Dict, List, Tuple
from urllib.parse import quote

import httpx

from ..core.result import ClaimStatus, SourceSummary, UnifiedResult
from .pagecheck import PageSpec, decide, interpolate, load_wmn_specs

UA = "Mozilla/5.0 (X11; Linux x86_64; rv:129.0) Gecko/20100101 Firefox/129.0"


def _load_known() -> Dict[str, List[str]]:
    """Known-claimed sample usernames, used as offline confirmation evidence."""
    raw = json.loads((Path(__file__).resolve().parent.parent / "data" / "wmn-data.json").read_text(encoding="utf-8"))
    known: Dict[str, List[str]] = {}
    from ..core.normalize import site_key
    for info in raw.get("sites", []):
        if info.get("known"):
            key = site_key(info.get("uri_check", "").replace("{account}", "x"))
            known[key] = [str(k).lower() for k in info["known"]]
    return known


async def _check_one(
    spec: PageSpec,
    target: str,
    client: httpx.AsyncClient,
    sem: asyncio.Semaphore,
) -> Tuple[PageSpec, ClaimStatus, int, str]:
    async with sem:
        quoted = quote(target, safe="")
        url_user = interpolate(spec.url_user, quoted)
        if not url_user:
            return spec, ClaimStatus.SKIPPED, 0, ""
        try:
            resp = await client.get(
                url_user,
                headers={"User-Agent": UA, "Accept": "text/html,application/xhtml+xml,*/*"},
                follow_redirects=True,
            )
        except Exception:
            return spec, ClaimStatus.UNKNOWN, 0, url_user

        try:
            text = resp.text[:600_000]
        except Exception:
            text = ""

        status = decide(spec, resp.status_code, text)
        return spec, status, resp.status_code, url_user


async def scan(target: str, target_type: str, cfg) -> Tuple[List[UnifiedResult], SourceSummary]:
    summary = SourceSummary(name="whatsmyname")
    if target_type == "email":
        summary.available = False
        summary.note = "username-only source"
        return [], summary

    start = time.time()
    specs = load_wmn_specs()
    if cfg.no_nsfw:
        specs = {k: v for k, v in specs.items() if not v.nsfw}
    if cfg.sites:
        from ..core.normalize import site_match
        specs = {k: v for k, v in specs.items() if site_match(v.name, v.url_user, cfg.sites)}
    if cfg.top_wmn and cfg.top_wmn > 0:
        # keep the freshest slice of the list (it is popularity ordered upstream)
        keys = list(specs.keys())[: cfg.top_wmn]
        specs = {k: specs[k] for k in keys}

    known = _load_known()
    tl = target.lower()

    out: List[UnifiedResult] = []
    sem = asyncio.Semaphore(cfg.max_concurrent)

    # Sites that list this exact username as known-claimed need no request at all.
    pending: List[PageSpec] = []
    for spec in specs.values():
        summary.checked += 1
        if tl in known.get(spec.key, []):
            summary.found += 1
            out.append(
                UnifiedResult(
                    target=target,
                    target_type=target_type,
                    source="wmn",
                    site=spec.name,
                    url=interpolate(spec.url_user, target),
                    status=ClaimStatus.EXISTS,
                    confidence=0.95,
                    method="wmn_known_sample",
                    extra={"note": "listed as known-claimed in WMN database"},
                )
            )
        else:
            pending.append(spec)

    async with httpx.AsyncClient(timeout=cfg.timeout) as client:
        tasks = [_check_one(s, target, client, sem) for s in pending]
        for coro in asyncio.as_completed(tasks):
            spec, status, http_status, url_user = await coro
            if status == ClaimStatus.EXISTS:
                summary.found += 1
            elif status == ClaimStatus.UNKNOWN:
                summary.errors += 1
            elif status == ClaimStatus.SKIPPED:
                summary.skipped += 1
                continue
            else:
                continue

            out.append(
                UnifiedResult(
                    target=target,
                    target_type=target_type,
                    source="wmn",
                    site=spec.name,
                    url=url_user,
                    status=status,
                    confidence=0.75,
                    method="wmn:e_code/e_string",
                    extra={"http_status": http_status} if http_status else {},
                )
            )

    summary.seconds = time.time() - start
    return out, summary
