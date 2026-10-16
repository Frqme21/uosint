"""Site identity normalization so results from different tools can be merged.

Sherlock says "Twitter" (twitter.com), DarkCurl says "X (Twitter)" (x.com) and
WhatsMyName says "twitter" — they must collapse into one row.
"""

from __future__ import annotations

import re
from typing import Optional
from urllib.parse import urlparse

# Multi-part public suffixes we care about (offline, no PSL dependency).
_MULTI_SUFFIX = {
    "co.uk", "org.uk", "ac.uk", "gov.uk", "me.uk", "net.uk", "sch.uk",
    "com.au", "net.au", "org.au", "edu.au", "gov.au", "id.au",
    "co.jp", "or.jp", "ne.jp", "ac.jp", "go.jp",
    "com.br", "net.br", "org.br", "com.cn", "net.cn", "org.cn", "gov.cn",
    "com.mx", "com.ar", "com.co", "com.tr", "com.tw", "com.hk", "com.sg",
    "co.in", "co.za", "co.kr", "co.nz", "co.id", "co.il", "co.ke",
    "com.ua", "com.ru", "com.pl", "com.es", "com.pt", "com.gr",
    "github.io", "gitlab.io", "pages.dev", "workers.dev",
}

# Known renames / mobile aliases -> canonical registrable domain.
_DOMAIN_ALIASES = {
    "twitter.com": "x.com",
    "mobile.twitter.com": "x.com",
    "m.twitter.com": "x.com",
    "t.co": "x.com",
    "x.com": "x.com",
    "instagram.com": "instagram.com",
    "m.facebook.com": "facebook.com",
    "mobile.facebook.com": "facebook.com",
    "touch.facebook.com": "facebook.com",
    "web.facebook.com": "facebook.com",
    "vk.com": "vk.com",
    "m.vk.com": "vk.com",
    "ok.ru": "ok.ru",
    "reddit.com": "reddit.com",
    "old.reddit.com": "reddit.com",
    "np.reddit.com": "reddit.com",
    "www.reddit.com": "reddit.com",
    "linkedin.com": "linkedin.com",
    "www.linkedin.com": "linkedin.com",
}

_SUBDOMAIN_STRIP = ("www.", "m.", "mobile.", "web.", "touch.", "old.", "np.")


def registrable_domain(host: str) -> str:
    """Best-effort registrable domain (eTLD+1) without a PSL dependency."""
    host = (host or "").strip().lower().rstrip(".")
    if not host:
        return ""
    # strip common mobile/prefix subdomains first
    for prefix in _SUBDOMAIN_STRIP:
        if host.startswith(prefix) and host.count(".") >= 2:
            host = host[len(prefix):]
            break
    labels = host.split(".")
    if len(labels) <= 2:
        return host
    last_two = ".".join(labels[-2:])
    if last_two in _MULTI_SUFFIX and len(labels) >= 3:
        return ".".join(labels[-3:])
    return last_two


def site_key(name_or_url: str) -> str:
    """Normalize a site name or URL into a merge key."""
    raw = (name_or_url or "").strip()
    if not raw:
        return ""

    candidate = raw
    if "://" in raw:
        parsed = urlparse(raw)
        candidate = parsed.netloc or raw
    elif "/" in raw and "." in raw:
        # bare domain/path like "github.com/user"
        candidate = raw.split("/")[0]

    # Some sources hand us bare names like "X (Twitter)" or "GitHubGist".
    if "." not in candidate:
        return _normalize_name(candidate)

    domain = registrable_domain(candidate)
    return _DOMAIN_ALIASES.get(domain, domain) or _normalize_name(raw)


def _normalize_name(name: str) -> str:
    """Normalize a bare site name (no domain) into a stable key."""
    cleaned = re.sub(r"[^a-z0-9]+", "", name.lower())
    aliases = {
        "xtwitter": "x.com",
        "twitter": "x.com",
        "x": "x.com",
        "github": "github.com",
        "reddit": "reddit.com",
        "instagram": "instagram.com",
        "facebook": "facebook.com",
        "linkedin": "linkedin.com",
        "tiktok": "tiktok.com",
        "snapchat": "snapchat.com",
        "tumblr": "tumblr.com",
        "pinterest": "pinterest.com",
        "youtube": "youtube.com",
        "mastodon": "mastodon.social",
        "googleplus": "plus.google.com",
    }
    if cleaned in aliases:
        return aliases[cleaned]
    return cleaned


def display_name(*candidates: str) -> str:
    """Pick a readable display name from candidates (prefer non-domain text)."""
    best = ""
    for c in candidates:
        if not c:
            continue
        if not best:
            best = c
        # prefer a name that contains a space or parenthetical (rich label)
        if " " in c or "(" in c:
            return c
        if len(c) < len(best) or best == "":
            best = c
    return best


def email_local_part(email: str) -> str:
    return email.split("@", 1)[0].strip().lower() if "@" in (email or "") else ""


def site_match(site_name: str, url: str, wanted: set) -> bool:
    """True when a site passes a user-supplied ``--sites`` filter.

    ``wanted`` holds normalized entries (lowercase) that may be domains
    (``github.com``), bare names (``reddit``) or display fragments
    (``GitHub`` vs DarkCurl's ``GitHub (User)``).
    """
    if not wanted:
        return True
    name = (site_name or "").strip().lower()
    if name in wanted:
        return True
    if url:
        key = site_key(url)
        if key in wanted:
            return True
    if site_name and site_key(site_name) in wanted:
        return True
    return any(e and e in name for e in wanted)


def email_domain(email: str) -> str:
    return email.split("@", 1)[1].strip().lower() if "@" in (email or "") else ""


EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
USERNAME_RE = re.compile(r"^[A-Za-z0-9._\- ]{1,64}$")


def is_email(value: str) -> bool:
    return bool(EMAIL_RE.match(value or ""))


def is_username(value: str) -> bool:
    return bool(USERNAME_RE.match(value or "")) and not is_email(value)
