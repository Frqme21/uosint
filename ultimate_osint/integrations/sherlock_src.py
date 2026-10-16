"""Sherlock integration — 400+ sites using its vendored database + detection logic."""

from __future__ import annotations

import asyncio
import time
from typing import Dict, List, Tuple
from urllib.parse import quote

import httpx

from ..core.normalize import site_key
from ..core.result import ClaimStatus, SourceSummary, UnifiedResult
from .pagecheck import PageSpec, decide, interpolate, load_sherlock_specs

UA = "Mozilla/5.0 (X11; Linux x86_64; rv:129.0) Gecko/20100101 Firefox/129.0"


async def _check_one(
    spec: PageSpec,
    target: str,
    client: httpx.AsyncClient,
    sem: asyncio.Semaphore,
) -> Tuple[PageSpec, ClaimStatus, int, str]:
    async with sem:
        # Username invalid for this site -> skipped, no request
        if spec.regex_check:
            import re
            if re.search(spec.regex_check, target) is None:
                return spec, ClaimStatus.SKIPPED, 0, ""

        quoted = quote(target, safe="")
        url_user = interpolate(spec.url_user, quoted)
        url_probe = interpolate(spec.url_probe, quoted) if spec.url_probe else url_user

        headers = {"User-Agent": UA}
        headers.update(spec.headers or {})

        follow = spec.engine != "response_url"
        try:
            method = spec.method.upper()
            if method in ("POST", "PUT"):
                payload = None
                if spec.request_payload:
                    payload = interpolate(spec.request_payload, quoted)
                resp = await client.request(method, url_probe, headers=headers, json=payload, follow_redirects=follow)
            elif method == "HEAD":
                resp = await client.head(url_probe, headers=headers, follow_redirects=follow)
            else:
                resp = await client.get(url_probe, headers=headers, follow_redirects=follow)
        except Exception:
            return spec, ClaimStatus.UNKNOWN, 0, ""

        text = ""
        if spec.engine != "status_code" or resp.status_code == 200:
            try:
                text = resp.text[:600_000]
            except Exception:
                text = ""

        status = decide(
            spec,
            resp.status_code,
            text,
            final_url=str(resp.url),
            username=target,
        )
        return spec, status, resp.status_code, url_user


async def scan(target: str, target_type: str, cfg) -> Tuple[List[UnifiedResult], SourceSummary]:
    summary = SourceSummary(name="sherlock")
    if target_type == "email":
        summary.available = False
        summary.note = "username-only source"
        return [], summary

    start = time.time()
    specs = load_sherlock_specs()
    if cfg.no_nsfw:
        specs = {k: v for k, v in specs.items() if not v.nsfw}
    if cfg.sites:
        from ..core.normalize import site_match
        specs = {k: v for k, v in specs.items() if site_match(v.name, v.url_user, cfg.sites)}

    sem = asyncio.Semaphore(cfg.max_concurrent)
    out: List[UnifiedResult] = []

    async with httpx.AsyncClient(timeout=cfg.timeout) as client:
        tasks = [_check_one(s, target, client, sem) for s in specs.values()]
        for coro in asyncio.as_completed(tasks):
            spec, status, http_status, url_user = await coro
            summary.checked += 1
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
                    source="sherlock",
                    site=spec.name,
                    url=url_user or interpolate(spec.url_user, target),
                    status=status,
                    confidence=0.75,
                    method=f"sherlock:{spec.engine}",
                    extra={"http_status": http_status} if http_status else {},
                )
            )

    summary.seconds = time.time() - start
    return out, summary
