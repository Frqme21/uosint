"""Third-party intel + DNS sources.

* Hudson Rock Cavalier — infostealer infection intel (explicit opt-in --hudson)
* EmailRep — email reputation / suspicious activity
* Have I Been Pwned — breach presence (optional API key)
* DNS/MX/SPF/DMARC analyzer + disposable/temp-mail detection (local)
"""

from __future__ import annotations

import asyncio
import os
import time
from typing import Any, Dict, List, Tuple

import httpx

from ..core.normalize import email_domain, email_local_part
from ..core.result import SourceSummary

UA = "ultimate-osint/0.1 (open-source OSINT aggregation)"

FREE_MAIL = {
    "gmail.com", "googlemail.com", "outlook.com", "hotmail.com", "live.com",
    "yahoo.com", "ymail.com", "aol.com", "proton.me", "protonmail.com",
    "icloud.com", "me.com", "mail.com", "gmx.com", "gmx.de", "mail.ru",
    "yandex.com", "yandex.ru", "zoho.com", "qq.com", "163.com", "126.com",
}

ROLE_ACCOUNTS = {
    "info", "admin", "administrator", "support", "sales", "contact",
    "help", "billing", "security", "abuse", "postmaster", "webmaster",
    "hostmaster", "noreply", "no-reply", "team", "office",
}

DISPOSABLE_DOMAINS = {
    "mailinator.com", "guerrillamail.com", "guerrillamail.info", "guerrillamail.net",
    "sharklasers.com", "spam4.me", "grr.la", "dispostable.com", "10minutemail.com",
    "minutemail.com", "throwawaymail.com", "tempmail.com", "temp-mail.org",
    "yopmail.com", "yopmail.fr", "trashmail.com", "trash-mail.com", "maildrop.cc",
    "mailnesia.com", "fakeinbox.com", "mailcatch.com", "tempr.email", "linshiyouxiang.net",
    "getnada.com", "disposablemail.com", "mohmal.com", "burnermail.io", "harakirimail.com",
    "tmail.ws", "mailnull.com", "spamgourmet.com", "mytemp.email", "emailondeck.com",
    "33mail.com", "rr.ze", "wegwerfemail.de", "einrot.com", "fleckens.hu",
    "t-online.de", "trashmail.de", "kasmail.com", "spamfree24.org", "dropmail.me",
    "tmpmail.net", "tmpmail.org", "grr.la", "sogetthis.com", "mailinator2.com",
    "pokemail.net", "spam4.me", "boun.cr", "bouncr.com", "cool.fr.nf",
    "courriel.fr.nf", "mega.zik.dj", "netcourrier.com", "freenet.fr.nf",
    "moncourrier.fr.nf", "monmail.fr.nf", "monemail.fr.nf", "neuf.fr",
    "teleworm.us", "dayrep.com", "rhyta.com", "einrot.de", "fleckens.de",
    "gustr.com", "superrito.com", "sidia.com", "igorannas.ru",
}


async def hudson(target: str, target_type: str, cfg) -> Tuple[Dict[str, Any], SourceSummary]:
    summary = SourceSummary(name="hudson")
    if not cfg.hudson:
        summary.available = False
        summary.note = "opt-in only (--hudson)"
        return {}, summary
    start = time.time()

    is_email = target_type == "email"
    endpoint = "search-by-email" if is_email else "search-by-username"
    param = "email" if is_email else "username"
    url = f"https://cavalier.hudsonrock.com/api/json/v2/osint-tools/{endpoint}?{param}={target}"

    block: Dict[str, Any] = {"source": "hudson_rock", "attribution": "Hudson Rock (https://www.hudsonrock.com)"}
    try:
        async with httpx.AsyncClient(timeout=15.0, headers={"User-Agent": UA}) as client:
            resp = await client.get(url)
        summary.checked = 1
        if resp.status_code != 200:
            summary.errors = 1
            summary.note = f"HTTP {resp.status_code}"
        else:
            data = resp.json()
            stealers = data.get("stealers") or []
            summary.found = len(stealers)
            block["exposed"] = bool(stealers)
            block["infections"] = [
                {
                    "stealer_family": s.get("stealer_family"),
                    "date_compromised": s.get("date_compromised"),
                    "operating_system": s.get("operating_system"),
                    "computer_name": s.get("computer_name"),
                    "antiviruses": s.get("antiviruses"),
                }
                for s in stealers[:20]
            ]
            if data.get("ostealers"):
                block["other_intel"] = {k: v for k, v in data.items() if k not in ("stealers",)}
    except Exception as e:
        summary.errors = 1
        summary.note = str(e)
        block = {}

    summary.seconds = time.time() - start
    return block, summary


async def emailrep(target: str, target_type: str, cfg) -> Tuple[Dict[str, Any], SourceSummary]:
    summary = SourceSummary(name="emailrep")
    if target_type != "email" or not cfg.emailrep:
        summary.available = False
        summary.note = "disabled" if not cfg.emailrep else "email-only source"
        return {}, summary
    start = time.time()

    key = os.environ.get("EMAILREP_API_KEY", "")
    headers = {"User-Agent": "uosint-research", "Accept": "application/json"}
    if key:
        headers["Key"] = key

    try:
        async with httpx.AsyncClient(timeout=15.0, headers=headers) as client:
            resp = await client.get(f"https://emailrep.io/{target}")
        summary.checked = 1
        if resp.status_code in (401, 403) and not key:
            summary.errors = 1
            summary.note = "needs API key (set EMAILREP_API_KEY)"
        elif resp.status_code == 429:
            summary.errors = 1
            summary.note = "rate limited (set EMAILREP_API_KEY for a higher quota)"
        elif resp.status_code != 200:
            summary.errors = 1
            summary.note = f"HTTP {resp.status_code}"
        else:
            data = resp.json()
            summary.found = 1 if data.get("suspicious") or data.get("reputation") in ("good", "neutral", "high") else 0
            block = {
                "source": "emailrep",
                "reputation": data.get("reputation"),
                "suspicious": data.get("suspicious"),
                "references": data.get("references"),
                "details": data.get("details") or {},
            }
            summary.seconds = time.time() - start
            return block, summary
    except Exception as e:
        summary.errors = 1
        summary.note = str(e)

    summary.seconds = time.time() - start
    return {}, summary


async def hibp(target: str, target_type: str, cfg) -> Tuple[Dict[str, Any], SourceSummary]:
    summary = SourceSummary(name="hibp")
    if target_type != "email":
        summary.available = False
        summary.note = "email-only source"
        return {}, summary
    key = cfg.hibp_key or os.environ.get("HIBP_API_KEY", "")
    if not key:
        summary.available = False
        summary.note = "no API key (set HIBP_API_KEY)"
        return {}, summary
    start = time.time()

    try:
        async with httpx.AsyncClient(
            timeout=20.0,
            headers={"User-Agent": "ultimate-osint", "hibp-api-key": key},
        ) as client:
            resp = await client.get(
                "https://haveibeenpwned.com/api/v3/breachedaccount/" + target,
                params={"truncateResponse": "false"},
            )
        summary.checked = 1
        if resp.status_code == 404:
            block = {"source": "hibp", "breaches": []}
            summary.seconds = time.time() - start
            return block, summary
        if resp.status_code == 429:
            summary.errors = 1
            summary.note = "rate limited"
        elif resp.status_code == 200:
            breaches = resp.json()
            summary.found = len(breaches)
            block = {
                "source": "hibp",
                "breaches": [
                    {"name": b.get("Name"), "date": b.get("BreachDate"), "data_classes": b.get("DataClasses")}
                    for b in breaches[:30]
                ],
            }
            summary.seconds = time.time() - start
            return block, summary
        else:
            summary.errors = 1
            summary.note = f"HTTP {resp.status_code}"
    except Exception as e:
        summary.errors = 1
        summary.note = str(e)

    summary.seconds = time.time() - start
    return {}, summary


async def dns_intel(target: str, target_type: str, cfg) -> Tuple[Dict[str, Any], SourceSummary]:
    summary = SourceSummary(name="dns")
    start = time.time()

    domain = email_domain(target) if target_type == "email" else ""
    if not domain:
        summary.available = False
        summary.note = "email-only source"
        return {}, summary

    summary.checked = 1
    block: Dict[str, Any] = {
        "source": "dns",
        "domain": domain,
        "provider": "free" if domain in FREE_MAIL else ("disposable" if domain in DISPOSABLE_DOMAINS else "custom"),
        "disposable": domain in DISPOSABLE_DOMAINS,
        "free_provider": domain in FREE_MAIL,
        "role_account": email_local_part(target) in ROLE_ACCOUNTS,
        "records": {},
    }

    def _query():
        import dns.resolver
        found = {}
        for label, rtype in (("mx", "MX"), ("spf", "TXT"), ("dmarc", "TXT")):
            try:
                if label == "dmarc":
                    answers = dns.resolver.resolve(f"_dmarc.{domain}", "TXT", lifetime=5)
                elif label == "spf":
                    answers = dns.resolver.resolve(domain, "TXT", lifetime=5)
                    answers = [a for a in answers if str(a).startswith("v=spf1")]
                else:
                    answers = dns.resolver.resolve(domain, "MX", lifetime=5)
                found[label] = [str(a).rstrip(".") for a in answers][:5]
            except Exception:
                found[label] = []
        try:
            found["a"] = [str(r) for r in dns.resolver.resolve(domain, "A", lifetime=5)][:4]
        except Exception:
            found["a"] = []
        return found

    try:
        records = await asyncio.to_thread(_query)
        block["records"] = records
        if records.get("mx"):
            summary.found = 1
        else:
            summary.note = "no MX (domain cannot receive mail)"
    except Exception as e:
        summary.errors = 1
        summary.note = str(e)

    summary.seconds = time.time() - start
    return block, summary
