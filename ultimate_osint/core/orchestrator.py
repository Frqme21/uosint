"""Runs every enabled source in parallel, aggregates claims, drives confirmation."""

from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Set, Tuple

from colorama import Fore, Style

from .confirm import confirm_all
from .normalize import email_local_part, is_email, site_key
from .result import ClaimStatus, ScanReport, SourceSummary, UnifiedResult
from ..integrations import (
    darkcurl_src,
    holehe_src,
    intel_src,
    maigret_src,
    sherlock_src,
    socialscan_src,
    wmn_src,
)


@dataclass
class UltimateConfig:
    """Everything the sources + confirm pass need to know."""

    target_type: str = "username"
    # scope
    deep: bool = False
    fast: bool = False
    no_nsfw: bool = False
    allow_loud: bool = False
    verbose: bool = False
    sites: Set[str] = field(default_factory=set)  # optional site filter
    sources: Optional[List[str]] = None  # None = all
    # limits
    top_maigret: int = 500
    top_wmn: int = 0  # 0 = all
    max_concurrent: int = 60
    timeout: float = 8.0
    # intel
    hudson: bool = False
    emailrep: bool = True
    hibp_key: str = ""
    # pivot (email mode: sweep discovered usernames too)
    pivot: bool = True
    pivot_deep: bool = False

    def wants(self, name: str) -> bool:
        if self.sources is None:
            return True
        return name in self.sources


# username claim sources, in execution order (order only affects display)
_USERNAME_SOURCES: List[Tuple[str, Callable]] = [
    ("darkcurl", darkcurl_src.scan),
    ("maigret", maigret_src.scan),
    ("sherlock", sherlock_src.scan),
    ("whatsmyname", wmn_src.scan),
    ("socialscan", socialscan_src.scan),
]

_EMAIL_SOURCES: List[Tuple[str, Callable]] = [
    ("darkcurl", darkcurl_src.scan),
    ("holehe", holehe_src.scan),
    ("socialscan", socialscan_src.scan),
]

_INTEL_SOURCES: List[Tuple[str, Callable]] = [
    ("hudson", intel_src.hudson),
    ("emailrep", intel_src.emailrep),
    ("hibp", intel_src.hibp),
    ("dns", intel_src.dns_intel),
]


async def _run_one(
    name: str,
    fn: Callable,
    target: str,
    target_type: str,
    cfg: UltimateConfig,
    report: ScanReport,
    print_line,
) -> List[UnifiedResult]:
    t0 = time.time()
    try:
        results, summary = await fn(target, target_type, cfg)
    except Exception as e:
        results, summary = [], SourceSummary(name=name, available=False, note=f"crashed: {e}")
        summary.seconds = time.time() - t0
    report.summaries.append(summary)
    if results:
        report.results.extend(results)
    print_line(name, summary)
    return results


async def run_scan(target: str, target_type: str, cfg: UltimateConfig) -> ScanReport:
    """Main entry: all sources -> cross-reference -> verification -> report."""
    report = ScanReport(target=target, target_type=target_type)

    if target_type == "email":
        claim_sources = _EMAIL_SOURCES
        intel_sources = _INTEL_SOURCES
    else:
        claim_sources = _USERNAME_SOURCES
        intel_sources = [s for s in _INTEL_SOURCES if s[0] in ("hudson",)]

    done = set()

    def print_line(name: str, s: SourceSummary):
        done.add(name)
        if not s.available:
            note = f" {Fore.WHITE}({s.note}){Style.RESET_ALL}" if s.note else ""
            print(f"  {Fore.YELLOW}[~]{Style.RESET_ALL} {name}: skipped{note}")
            return
        color = Fore.GREEN if s.found else Fore.WHITE
        flag = f" {Fore.RED}(degraded/rate-limited?){Style.RESET_ALL}" if s.degraded else ""
        note = f" {Fore.WHITE}({s.note}){Style.RESET_ALL}" if s.note else ""
        print(
            f"  {color}[+]{Style.RESET_ALL} {name}: {s.found} found / {s.checked} checked "
            f"/ {s.errors} errors in {s.seconds:.1f}s{flag}{note}"
        )

    print(f"\n{Fore.CYAN}[i] Phase 1/3 — querying sources for: {target}{Style.RESET_ALL}")
    tasks = [
        asyncio.create_task(_run_one(name, fn, target, target_type, cfg, report, print_line))
        for name, fn in claim_sources
        if cfg.wants(name)
    ]
    if tasks:
        await asyncio.gather(*tasks)

    # Intel (breach / reputation / dns) — independent, smaller
    async def run_intel():
        for name, fn in intel_sources:
            if not cfg.wants(name):
                continue
            try:
                block, summary = await fn(target, target_type, cfg)
            except Exception as e:
                block, summary = {}, SourceSummary(name=name, available=False, note=f"crashed: {e}")
            report.summaries.append(summary)
            if block:
                report.intel.append(block)
            print_line(name, summary)

    await run_intel()

    # ---- pivots: email mode -> sweep usernames it leaked ----
    if target_type == "email" and cfg.pivot:
        pivots = _discover_pivots(target, report)
        if pivots:
            report.pivots = pivots
            await _run_pivots(pivots, cfg, report, print_line)

    # ---- Phase 2: cross-reference + verification ----
    print(f"\n{Fore.CYAN}[i] Phase 2/3 — cross-referencing + live verification{Style.RESET_ALL}")
    positive = [r for r in report.results if r.status == ClaimStatus.EXISTS]
    unique_sites = len({(r.site_key or site_key(r.url or r.site)) for r in positive})
    if positive:
        print(f"  {Fore.WHITE}merging {len(positive)} claims -> {unique_sites} unique sites, verifying...{Style.RESET_ALL}")
        await confirm_all(report.results, cfg)
    else:
        print(f"  {Fore.YELLOW}[!] no positive claims to verify{Style.RESET_ALL}")

    return report


def _discover_pivots(email: str, report: ScanReport) -> List[str]:
    """Find usernames that this email's profiles point at."""
    import re

    valid = re.compile(r"^[A-Za-z0-9._-]{3,39}$")
    found: Set[str] = set()
    local = email_local_part(email)
    if local and len(local) >= 3:
        found.add(local)

    for r in report.results:
        if r.status != ClaimStatus.EXISTS:
            continue
        for key in ("username", "login_name", "screen_name", "handle", "user"):
            val = str(r.extra.get(key, "") or "").strip()
            if valid.match(val) and val.lower() != local.lower():
                found.add(val.lower())

    # drop obvious noise
    noise = {"none", "null", "true", "false", "unknown", "private", "test", "user"}
    found -= noise
    return sorted(found)[:5]


async def _run_pivots(
    usernames: List[str],
    cfg: UltimateConfig,
    report: ScanReport,
    print_line,
) -> None:
    """Second sweep: username sources for every pivot (email mode)."""
    print(
        f"\n{Fore.CYAN}[i] Phase 1b/3 — pivoting to usernames discovered from profiles: "
        f"{', '.join(usernames)}{Style.RESET_ALL}"
    )
    # Lighter set for pivots unless --deep: darkcurl covers the metadata,
    # sherlock + WMN give independent confirmation.
    pivot_sources = [
        ("darkcurl", darkcurl_src.scan),
        ("sherlock", sherlock_src.scan),
        ("whatsmyname", wmn_src.scan),
    ]
    if cfg.pivot_deep or cfg.deep:
        pivot_sources.insert(1, ("maigret", maigret_src.scan))

    from dataclasses import replace as _replace
    sub = _replace(cfg)
    sub.sites = cfg.sites
    sub.sources = None
    if cfg.fast:
        sub.top_wmn = 300

    for uname in usernames:
        tasks = [
            asyncio.create_task(_run_one(name, fn, uname, "username", sub, report, print_line))
            for name, fn in pivot_sources
            if cfg.wants(name)
        ]
        if tasks:
            await asyncio.gather(*tasks)
