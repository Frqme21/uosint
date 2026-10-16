"""Console + JSON/CSV reporting."""

from __future__ import annotations

import csv
import io
import json
from collections import Counter
from datetime import datetime, timezone
from typing import List

from colorama import Fore, Style

from .result import ScanReport, UnifiedResult, Verdict
from .confirm import merged_display


def _source_badges(claims: List[UnifiedResult]) -> str:
    names = sorted({c.source for c in claims})
    return ", ".join(names)


def _best_url(claims: List[UnifiedResult]) -> str:
    """URL most sources agree on; ties go to a claim that carries metadata."""
    urls = [c.url.rstrip("/") for c in claims if c.url]
    if not urls:
        return ""
    counts = Counter(urls)
    best_count = max(counts.values())
    candidates = {u for u, n in counts.items() if n == best_count}
    for c in claims:
        if c.url.rstrip("/") in candidates and c.extra:
            return c.url
    return next(c.url for c in claims if c.url.rstrip("/") in candidates)


def print_report(report: ScanReport, show_unconfirmed: bool = False, verbose: bool = False) -> None:
    confirmed = report.confirmed
    likely = report.likely
    unverified = report.unverified
    refuted = report.refuted

    print(f"\n{Fore.CYAN}{'=' * 64}{Style.RESET_ALL}")
    label = "EMAIL" if report.target_type == "email" else "USERNAME"
    print(f"{Fore.CYAN} RESULTS FOR {label}: {report.target}{Style.RESET_ALL}")
    print(f"{Fore.CYAN}{'=' * 64}{Style.RESET_ALL}")

    rows = merged_display([r for r in report.results if r.verdict in (Verdict.CONFIRMED, Verdict.LIKELY)])

    confirmed_rows = [(k, n, c) for k, n, c in rows if any(x.verdict == Verdict.CONFIRMED for x in c)]
    likely_rows = [(k, n, c) for k, n, c in rows if not any(x.verdict == Verdict.CONFIRMED for x in c)]

    print(f"\n{Fore.GREEN}{Style.BRIGHT}✔ CONFIRMED ACCOUNTS ({len(confirmed_rows)} sites){Style.RESET_ALL}")
    if not confirmed_rows:
        print(f"  {Fore.WHITE}(none){Style.RESET_ALL}")
    for _, name, claims in sorted(confirmed_rows, key=lambda r: r[0]):
        best = next((c for c in claims if c.extra), claims[0])
        consensus = max(c.consensus for c in claims)
        cons = f" {Fore.YELLOW}x{consensus}{Style.RESET_ALL}" if consensus > 1 else ""
        url = _best_url(claims)
        src = _source_badges(claims)
        print(f"  {Fore.GREEN}[✓]{Style.RESET_ALL} {name} {Fore.WHITE}({src}){cons}{Style.RESET_ALL}")
        if url:
            print(f"      {Fore.WHITE}{url}{Style.RESET_ALL}")
        reason = best.verdict_reason
        if reason:
            print(f"      {Fore.WHITE}{reason}{Style.RESET_ALL}")
        if verbose and best.evidence:
            for k, v in best.evidence.items():
                print(f"      {Fore.CYAN}{k}:{Style.RESET_ALL} {v}")
        if best.extra and best.source == "darkcurl":
            for k, v in list(best.extra.items())[:8]:
                print(f"      {Fore.CYAN}{k}:{Style.RESET_ALL} {v}")
        elif best.extra:
            for k, v in list(best.extra.items())[:4]:
                print(f"      {Fore.CYAN}{k}:{Style.RESET_ALL} {v}")

    print(f"\n{Fore.YELLOW}{Style.BRIGHT}◌ LIKELY ({len(likely_rows)} sites — single source, worth a look){Style.RESET_ALL}")
    if not likely_rows:
        print(f"  {Fore.WHITE}(none){Style.RESET_ALL}")
    for _, name, claims in sorted(likely_rows, key=lambda r: r[0]):
        best = claims[0]
        url = _best_url(claims)
        print(f"  {Fore.YELLOW}[~]{Style.RESET_ALL} {name} {Fore.WHITE}({_source_badges(claims)}){Style.RESET_ALL}")
        if url:
            print(f"      {Fore.WHITE}{url}{Style.RESET_ALL}")

    if show_unconfirmed or verbose:
        if unverified:
            print(f"\n{Fore.WHITE}◌ UNVERIFIED / CONFLICTING ({len(unverified)} claims){Style.RESET_ALL}")
            for r in sorted(unverified, key=lambda x: x.site_key):
                print(f"  {Fore.WHITE}[?]{Style.RESET_ALL} {r.site} ({r.source}): {r.verdict_reason}")
                if r.url:
                    print(f"      {Fore.WHITE}{r.url}{Style.RESET_ALL}")
        if refuted:
            print(f"\n{Fore.WHITE}✘ REFUTED — live check contradicts ({len(refuted)} claims){Style.RESET_ALL}")
            for r in sorted(refuted, key=lambda x: x.site_key):
                print(f"  {Fore.WHITE}[✘]{Style.RESET_ALL} {r.site} ({r.source}): {r.verdict_reason}")

    # ---- intel blocks ----
    if report.intel:
        print(f"\n{Fore.MAGENTA}{Style.BRIGHT}◆ THREAT / REPUTATION INTEL{Style.RESET_ALL}")
        for block in report.intel:
            src = block.get("source", "?")
            if src == "hudson_rock":
                if block.get("exposed"):
                    print(f"  {Fore.RED}[!] Hudson Rock: infostealer infection(s) linked to this identifier{Style.RESET_ALL}")
                    for inf in block.get("infections", [])[:5]:
                        print(
                            f"      family={inf.get('stealer_family')} "
                            f"date={inf.get('date_compromised')} "
                            f"os={inf.get('operating_system')} "
                            f"computer={inf.get('computer_name')}"
                        )
                else:
                    print(f"  {Fore.GREEN}[✓] Hudson Rock: no infostealer infections found{Style.RESET_ALL}")
            elif src == "emailrep":
                rep = block.get("reputation")
                susp = block.get("suspicious")
                col = Fore.RED if susp else Fore.GREEN
                print(f"  {col}[{'!' if susp else '✓'}] EmailRep: reputation={rep} suspicious={susp}{Style.RESET_ALL}")
                details = block.get("details") or {}
                interesting = {k: v for k, v in details.items() if v and k in (
                    "credentials_leaked", "data_breach", "malicious_activity",
                    "spam", "free_provider", "domain_exists", "profiles",
                )}
                for k, v in list(interesting.items())[:8]:
                    print(f"      {k}: {v}")
            elif src == "hibp":
                breaches = block.get("breaches") or []
                if breaches:
                    print(f"  {Fore.RED}[!] HaveIBeenPwned: {len(breaches)} breach(es){Style.RESET_ALL}")
                    for b in breaches[:8]:
                        print(f"      {b.get('name')} ({b.get('date')}): {', '.join(b.get('data_classes') or [])}")
                else:
                    print(f"  {Fore.GREEN}[✓] HaveIBeenPwned: no breaches found{Style.RESET_ALL}")
            elif src == "dns":
                rec = block.get("records") or {}
                prov = block.get("provider")
                if block.get("disposable"):
                    print(f"  {Fore.RED}[!] Disposable/temp-mail domain: {block.get('domain')}{Style.RESET_ALL}")
                elif block.get("free_provider"):
                    print(f"  {Fore.YELLOW}[i] Free mail provider: {block.get('domain')}{Style.RESET_ALL}")
                else:
                    print(f"  {Fore.GREEN}[i] Custom domain: {block.get('domain')} ({prov}){Style.RESET_ALL}")
                if block.get("role_account"):
                    print(f"  {Fore.YELLOW}[i] Role account (info/admin/etc){Style.RESET_ALL}")
                if rec.get("mx"):
                    print(f"      MX: {', '.join(rec['mx'][:3])}")
                if rec.get("spf"):
                    print(f"      SPF: {rec['spf'][0][:90]}")
                if rec.get("dmarc"):
                    print(f"      DMARC: {rec['dmarc'][0][:90]}")
                elif not rec.get("dmarc"):
                    print(f"      {Fore.YELLOW}DMARC: none published{Style.RESET_ALL}")

    # ---- pivots ----
    if report.pivots:
        print(f"\n{Fore.CYAN}{Style.BRIGHT}↗ DISCOVERED IDENTIFIERS (pivot){Style.RESET_ALL}")
        print(f"  {', '.join(report.pivots)}")
        print(f"  {Fore.WHITE}sweep them too: ultimate-osint -u <username>{Style.RESET_ALL}")

    # ---- source stats ----
    print(f"\n{Fore.CYAN}◆ SOURCE STATS{Style.RESET_ALL}")
    for s in report.summaries:
        if not s.available and not s.note:
            continue
        if not s.available:
            print(f"  {Fore.YELLOW}[~]{Style.RESET_ALL} {s.name}: {s.note}")
        else:
            flag = f" {Fore.RED}(degraded){Style.RESET_ALL}" if s.degraded else ""
            print(
                f"  {Fore.WHITE}[-]{Style.RESET_ALL} {s.name}: {s.found}/{s.checked} found, "
                f"{s.errors} errors, {s.skipped} skipped, {s.seconds:.1f}s{flag}"
            )

    total_conf = len(report.confirmed)
    total_lik = len(report.likely)
    print(
        f"\n{Fore.GREEN}{Style.BRIGHT}CONFIRMED: {total_conf}{Style.RESET_ALL}"
        f"  {Fore.YELLOW}LIKELY: {total_lik}{Style.RESET_ALL}"
        f"  {Fore.WHITE}unverified: {len(unverified)}, refuted: {len(refuted)}{Style.RESET_ALL}"
    )
    if unverified or refuted:
        print(f"  {Fore.WHITE}(re-run with --show-unconfirmed or -v to inspect them){Style.RESET_ALL}")


def into_json(report: ScanReport) -> str:
    counts = Counter(r.verdict.value for r in report.results if r.verdict)
    data = {
        "tool": "ultimate-osint",
        "version": "0.1.0",
        "target": report.target,
        "target_type": report.target_type,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "stats": dict(counts),
        "intel": report.intel,
        "pivots": report.pivots,
        "sources": [s.to_dict() for s in report.summaries],
        "results": [r.to_dict() for r in report.results if r.status.value == "exists"],
    }
    return json.dumps(data, indent=2, ensure_ascii=False, default=str)


def into_csv(report: ScanReport) -> str:
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(
        ["target", "site", "site_key", "url", "verdict", "consensus", "sources", "method", "extra", "reason"]
    )
    groups = {}
    for r in report.results:
        if r.status.value != "exists":
            continue
        groups.setdefault(r.site_key or r.site, []).append(r)

    for key, claims in sorted(groups.items()):
        best = next((c for c in claims if c.extra), claims[0])
        writer.writerow(
            [
                best.target,
                best.site,
                key,
                _best_url(claims),
                best.verdict.value if best.verdict else "",
                max(c.consensus for c in claims),
                ";".join(sorted({c.source for c in claims})),
                best.method,
                "; ".join(f"{k}={v}" for k, v in best.extra.items())[:400],
                best.verdict_reason,
            ]
        )
    return buf.getvalue()
