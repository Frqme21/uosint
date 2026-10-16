#!/usr/bin/env python3
"""Ultimate OSINT Suite CLI."""

from __future__ import annotations

import argparse
import asyncio
import sys
from datetime import datetime, timezone
from pathlib import Path

from colorama import Fore, Style, init as colorama_init

from .core.orchestrator import UltimateConfig, run_scan
from .core.report import into_csv, into_json, print_report
from .core.normalize import is_email

colorama_init(autoreset=True)

ALL_SOURCES = [
    "darkcurl", "maigret", "sherlock", "whatsmyname",
    "holehe", "socialscan", "hudson", "emailrep", "hibp", "dns",
]


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="ultimate-osint",
        description="The ultimate OSINT suite: DarkCurl + Maigret + Sherlock + WhatsMyName + "
        "Holehe + Socialscan + breach/reputation intel, cross-referenced and verified.",
        epilog="Only CONFIRMED / LIKELY findings are shown by default — every claim is "
        "cross-referenced across sources and re-verified live before it is reported.",
    )
    g = p.add_mutually_exclusive_group(required=True)
    g.add_argument("-u", "--username", help="Username to investigate")
    g.add_argument("-e", "--email", help="Email address to investigate")
    g.add_argument("-uf", "--username-file", help="File of usernames (one per line)")
    g.add_argument("-ef", "--email-file", help="File of emails (one per line)")
    g.add_argument("--list-sources", action="store_true", help="List all sources and exit")

    p.add_argument("-s", "--sources", help=f"Comma list of sources to use (default all): {','.join(ALL_SOURCES)}")
    p.add_argument("--fast", action="store_true", help="Quick pass (fewer sites, no deep parsing)")
    p.add_argument("--deep", action="store_true", help="Everything: all Maigret sites, all pivots")
    p.add_argument("--sites", help="Comma list of site keys/names to restrict checks to (e.g. github.com,reddit)")
    p.add_argument("--no-nsfw", action="store_true", help="Skip adult sites")
    p.add_argument("--allow-loud", action="store_true",
                   help="Include DarkCurl 'loud' modules (may trigger password-reset emails)")
    p.add_argument("--hudson", action="store_true",
                   help="Query Hudson Rock infostealer API (sends the identifier to a third party)")
    p.add_argument("--no-emailrep", action="store_true", help="Disable EmailRep reputation lookup")
    p.add_argument("--hibp-key", help="Have I Been Pwned API key (or set HIBP_API_KEY)")
    p.add_argument("--no-pivot", action="store_true",
                   help="Email mode: do not sweep usernames discovered from found profiles")
    p.add_argument("--show-unconfirmed", action="store_true", help="Also show unverified/refuted claims")
    p.add_argument("-v", "--verbose", action="store_true", help="Verbose output (full evidence, all claims)")
    p.add_argument("--max-concurrent", type=int, default=60, help="Max concurrent requests per source (default 60)")
    p.add_argument("--timeout", type=float, default=8.0, help="Per-request timeout seconds (default 8)")
    p.add_argument("-o", "--output", help="Write report to file (.json or .csv)")
    p.add_argument("-f", "--format", choices=["json", "csv"], help="Output format (default: from extension)")
    return p


def load_targets(args) -> tuple[list[str], str]:
    if args.username:
        return [args.username.strip()], "username"
    if args.email:
        return [args.email.strip()], "email"
    path = args.username_file or args.email_file
    target_type = "username" if args.username_file else "email"
    lines = Path(path).read_text(encoding="utf-8").splitlines()
    targets = [ln.strip() for ln in lines if ln.strip() and not ln.startswith("#")]
    if target_type == "email":
        bad = [t for t in targets if not is_email(t)]
        for t in bad:
            print(f"{Fore.YELLOW}[!] skipping invalid email: {t}{Style.RESET_ALL}")
        targets = [t for t in targets if is_email(t)]
    if not targets:
        print(f"{Fore.RED}[✘] no valid targets in {path}{Style.RESET_ALL}")
        sys.exit(1)
    return targets, target_type


def config_from(args) -> UltimateConfig:
    sites = set()
    if args.sites:
        sites = {s.strip().lower() for s in args.sites.split(",") if s.strip()}
    sources = None
    if args.sources:
        sources = {s.strip().lower() for s in args.sources.split(",") if s.strip()}
        unknown = sources - set(ALL_SOURCES)
        if unknown:
            print(f"{Fore.RED}[✘] unknown sources: {', '.join(sorted(unknown))}{Style.RESET_ALL}")
            sys.exit(1)
    cfg = UltimateConfig(
        deep=args.deep,
        fast=args.fast,
        no_nsfw=args.no_nsfw,
        allow_loud=args.allow_loud,
        verbose=args.verbose,
        sites=sites,
        sources=sorted(sources) if sources else None,
        max_concurrent=args.max_concurrent,
        timeout=args.timeout,
        hudson=args.hudson,
        emailrep=not args.no_emailrep,
        hibp_key=args.hibp_key or "",
        pivot=not args.no_pivot,
    )
    if args.fast:
        cfg.top_maigret = 150
        cfg.top_wmn = 350
        cfg.timeout = min(cfg.timeout, 6.0)
        cfg.max_concurrent = min(cfg.max_concurrent, 60)
    if args.deep:
        cfg.top_maigret = 0  # all
        cfg.top_wmn = 0
        cfg.pivot_deep = True
    return cfg


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()

    if args.list_sources:
        print(f"{Fore.CYAN}Available sources:{Style.RESET_ALL}")
        rows = [
            ("darkcurl", "295+ username/email modules, rich metadata extraction", "user+email"),
            ("maigret", "3187+ site username database", "user"),
            ("sherlock", "413-site username sweep (vendored DB, MIT)", "user"),
            ("whatsmyname", "692-site community database (CC BY-SA 4.0)", "user"),
            ("holehe", "149 register / forgot-password email checks", "email"),
            ("socialscan", "signup-API availability checks (highest accuracy)", "user+email"),
            ("hudson", "Hudson Rock infostealer infection intel (--hudson opt-in)", "user+email"),
            ("emailrep", "email reputation + suspicious activity", "email"),
            ("hibp", "Have I Been Pwned breaches (needs API key)", "email"),
            ("dns", "MX / SPF / DMARC / disposable-domain analysis (local)", "email"),
        ]
        for name, desc, kind in rows:
            print(f"  {Fore.GREEN}{name:14}{Style.RESET_ALL} {desc} {Fore.WHITE}[{kind}]{Style.RESET_ALL}")
        return

    targets, target_type = load_targets(args)
    cfg = config_from(args)
    cfg.target_type = target_type

    print(f"{Fore.CYAN}{Style.BRIGHT}=== ULTIMATE OSINT SUITE ==={Style.RESET_ALL}")
    print(
        f"{Fore.WHITE}sources: DarkCurl + Maigret + Sherlock + WhatsMyName + Holehe + Socialscan "
        f"+ Hudson Rock + EmailRep + HIBP + DNS{Style.RESET_ALL}"
    )
    print(f"{Fore.WHITE}mode: {'FAST' if cfg.fast else 'DEEP' if cfg.deep else 'FULL'} | "
          f"targets: {len(targets)} {target_type} | cross-reference: on | verification: on{Style.RESET_ALL}")
    if cfg.hudson:
        print(f"{Fore.YELLOW}[i] --hudson: identifiers will be sent to Hudson Rock's public API{Style.RESET_ALL}")

    all_reports = []
    failed = 0
    for i, target in enumerate(targets, 1):
        if len(targets) > 1:
            print(f"\n{Fore.MAGENTA}{Style.BRIGHT}>>> Target {i}/{len(targets)}: {target}{Style.RESET_ALL}")
        try:
            report = asyncio.run(run_scan(target, target_type, cfg))
        except KeyboardInterrupt:
            print(f"\n{Fore.YELLOW}[!] interrupted{Style.RESET_ALL}")
            break
        except Exception as e:
            failed += 1
            print(f"{Fore.RED}[✘] {target} failed: {e}{Style.RESET_ALL}")
            if args.verbose:
                import traceback
                traceback.print_exc()
            continue
        all_reports.append(report)
        print_report(report, show_unconfirmed=args.show_unconfirmed, verbose=args.verbose)

    if args.output and all_reports:
        fmt = args.format or (Path(args.output).suffix.lstrip(".").lower() or "json")
        try:
            if fmt == "csv":
                content = "\n".join(into_csv(r) for r in all_reports)
            else:
                if len(all_reports) == 1:
                    content = into_json(all_reports[0])
                else:
                    import json
                    content = json.dumps(
                        [json.loads(into_json(r)) for r in all_reports],
                        indent=2, ensure_ascii=False, default=str,
                    )
            Path(args.output).write_text(content, encoding="utf-8")
            print(f"{Fore.GREEN}[+] report written to {args.output}{Style.RESET_ALL}")
        except Exception as e:
            print(f"{Fore.RED}[✘] failed to write output: {e}{Style.RESET_ALL}")

    if not all_reports and failed:
        sys.exit(1)


def run() -> None:
    main()


if __name__ == "__main__":
    run()
