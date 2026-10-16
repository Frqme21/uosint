"""Shared HTTP page-existence checking engine.

Replicates the detection logic of two upstream OSINT projects against their
vendored site databases:

* Sherlock  (sherlock-project/sherlock, MIT)   -> ``errorType`` specs
* WhatsMyName (WebBreacher/WhatsMyName, CC BY-SA 4.0) -> ``e_code/e_string``
  style specs

The decision functions are pure (status, text, spec) -> verdict so they can be
unit tested offline without any network.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse

from ..core.result import ClaimStatus

DATA_DIR = Path(__file__).resolve().parent.parent / "data"

# WAF fingerprints (from Sherlock, MIT) -> treat as UNKNOWN, never a finding.
WAF_MARKERS = [
    r".loading-spinner{visibility:hidden}body.no-js .challenge-running{display:none}body.dark{background-color:#222;color:#d9d9d9}body.dark a{color:#fff}body.dark a:hover{color:#ee730a;text-decoration:underline}body.dark .lds-ring div{border-color:#999 transparent transparent}body.dark .font-red{color:#b20f03}body.dark",
    r'<span id="challenge-error-text">',
    r"AwsWafIntegration.forceRefreshToken",
    r"{return l.onPageView}}),Object.defineProperty(r,\"perimeterxIdentifiers\",{enumerable:",
]

_BLOCK_STATUSES = {401, 403, 407, 429, 451, 475, 503, 520, 521, 522, 523, 525, 530}


@dataclass
class PageSpec:
    """Normalized existence spec for one site."""

    key: str  # site_key (domain)
    name: str
    url_user: str  # profile URL template
    url_probe: Optional[str] = None  # probe URL template (different from profile)
    method: str = "GET"
    engine: str = "status_code"  # status_code | message | response_url | wmn
    # sherlock style
    error_codes: Optional[List[int]] = None
    error_msgs: Optional[List[str]] = None
    error_url: Optional[str] = None
    # whatsmyname style
    e_code: Optional[int] = None
    e_string: str = ""
    m_code: Optional[int] = None
    m_string: str = ""
    regex_check: Optional[str] = None
    headers: Dict[str, str] = None  # type: ignore[assignment]
    request_payload: Any = None
    nsfw: bool = False

    def __post_init__(self):
        if self.headers is None:
            self.headers = {}


def interpolate(template: str, username: str) -> str:
    """Sherlock uses {}, WhatsMyName uses {account}."""
    if not template:
        return ""
    return template.replace("{account}", username).replace("{}", username)


def _waf_hit(text: str) -> bool:
    return any(m in text for m in WAF_MARKERS)


# ---------------------------------------------------------------------------
# Redirect / interstitial guards
# ---------------------------------------------------------------------------

_HOST_PREFIXES = ("www.", "m.", "mobile.", "amp.", "beta.")

# Path fragments that mean "we were bounced to a wall", never a profile page.
_INTERSTITIAL_HINTS = (
    "/verify-human",
    "/verify",
    "/consent",
    "/captcha",
    "/challenge",
    "/login",
    "/signin",
    "/sign-in",
    "/age-check",
    "/agecheck",
    "/gdpr",
    "/cookie",
    "/interstitial",
    "/blocked",
    "/challenge-platform",
)


def _host(url: str) -> str:
    try:
        return (urlparse(url).hostname or "").lower()
    except Exception:
        return ""


def _norm_host(host: str) -> str:
    for prefix in _HOST_PREFIXES:
        if host.startswith(prefix):
            return host[len(prefix):]
    return host


def is_interstitial(final_url: str, probe_url: str) -> bool:
    """True when a fetch was bounced to a consent/auth/CDN domain or wall page.

    A redirect that leaves the site (``consent.youtube.com`` for
    ``www.youtube.com``, ``threads.com`` for ``threads.net``) means we never
    actually saw the profile, so the result must not count as confirmation.
    """
    if not final_url or not probe_url:
        return False
    final_host, probe_host = _host(final_url), _host(probe_url)
    if final_host and probe_host and _norm_host(final_host) != _norm_host(probe_host):
        return True
    path = (urlparse(final_url).path or "").lower()
    return any(hint in path for hint in _INTERSTITIAL_HINTS)


# Search / query endpoints return results *about* a handle, never proof the
# handle owns a profile there.
_SEARCH_HINTS = ("search", "/query", "?q=", "&q=", "query=", "search_text", "searchtext")


def looks_like_search(url: str, handle: str = "") -> bool:
    """True for search/lookup endpoints.

    Covers explicit result pages (``/search?q=``) **and** lookup URLs that pass
    the handle as a query value (``member.php?username=darkcurl``) — those echo
    the handle back without the account necessarily existing.
    """
    low = (url or "").lower()
    if not low:
        return False
    if any(hint in low for hint in _SEARCH_HINTS):
        return True
    if handle and len(handle) >= 3:
        try:
            query = urlparse(url).query.lower()
        except Exception:
            query = ""
        if query and handle.lower() in query:
            return True
    return False


def has_search_path(url: str) -> bool:
    """True when the URL *path* is a search endpoint (results list, not a profile).

    Narrower than :func:`looks_like_search`: a query-string lookup API such as
    ``/api/users?name={handle}`` is fine, ``/search/{handle}`` is not.
    """
    try:
        path = urlparse(url).path.lower()
    except Exception:
        return False
    return "search" in path or "/query" in path


# ---------------------------------------------------------------------------
# Pure decision functions
# ---------------------------------------------------------------------------

def decide_sherlock(spec: PageSpec, status: int, text: str, final_url: str = "", username: str = "") -> ClaimStatus:
    """Sherlock errorType logic (MIT), hardened for precision.

    Upstream treats any non-error 2xx as "exists", which turns soft-404s and
    consent/interstitial pages into false positives. Two extra guards keep only
    real profiles:

    * only HTTP 200 counts as a hit (201/202/... are never profile pages), and
    * when we know the handle, it must actually appear in the page body.
    """
    if _waf_hit(text):
        return ClaimStatus.UNKNOWN
    if status in _BLOCK_STATUSES:
        return ClaimStatus.UNKNOWN

    def _soft_404() -> bool:
        return _has_missing_marker(text)

    def _handle_seen() -> bool:
        # No (or too short) handle -> caller opted out of body corroboration.
        if not username or len(username) < 3:
            return True
        return username.lower() in text.lower()

    if spec.engine == "message":
        errors = spec.error_msgs or []
        if any(e in text for e in errors):
            return ClaimStatus.NOT_EXISTS
        if status in (200, 201):
            if _soft_404():
                return ClaimStatus.NOT_EXISTS
            return ClaimStatus.EXISTS if _handle_seen() else ClaimStatus.UNKNOWN
        if 200 <= status < 300:
            return ClaimStatus.EXISTS if _handle_seen() else ClaimStatus.UNKNOWN
        if status >= 400:
            return ClaimStatus.UNKNOWN
        return ClaimStatus.EXISTS

    if spec.engine == "status_code":
        codes = spec.error_codes or []
        if status in codes:
            return ClaimStatus.NOT_EXISTS
        if status == 200:
            if _soft_404():
                return ClaimStatus.NOT_EXISTS
            return ClaimStatus.EXISTS if _handle_seen() else ClaimStatus.UNKNOWN
        if 200 <= status < 300:
            return ClaimStatus.UNKNOWN
        if status >= 300:
            return ClaimStatus.NOT_EXISTS
        return ClaimStatus.UNKNOWN

    if spec.engine == "response_url":
        # redirects were disallowed; a clean 2xx means the profile exists
        if 200 <= status < 300:
            return ClaimStatus.EXISTS
        if 300 <= status < 400:
            return ClaimStatus.NOT_EXISTS
        if status in _BLOCK_STATUSES:
            return ClaimStatus.UNKNOWN
        return ClaimStatus.NOT_EXISTS

    return ClaimStatus.UNKNOWN


def decide_wmn(spec: PageSpec, status: int, text: str) -> ClaimStatus:
    """WhatsMyName existence logic.

    exists      : status == e_code AND (no e_string OR e_string present)
                  AND (no m_string OR m_string absent)
    not exists  : status == m_code OR m_string present (when defined)
    unknown     : everything else (rate limits, WAFs, soft errors)
    """
    if _waf_hit(text):
        return ClaimStatus.UNKNOWN
    if status == 429:
        return ClaimStatus.UNKNOWN
    if status in _BLOCK_STATUSES and status not in (spec.e_code, spec.m_code):
        return ClaimStatus.UNKNOWN

    m_string_hit = bool(spec.m_string) and spec.m_string in text
    e_string_ok = (not spec.e_string) or (spec.e_string in text)

    if spec.m_string and m_string_hit:
        return ClaimStatus.NOT_EXISTS

    if spec.e_code is not None and status == spec.e_code and e_string_ok:
        if spec.e_code in (403, 401, 429) and not spec.e_string:
            # an unauthenticated 403 with no marker proves nothing
            return ClaimStatus.UNKNOWN
        return ClaimStatus.EXISTS

    if spec.m_code is not None and status == spec.m_code:
        return ClaimStatus.NOT_EXISTS

    return ClaimStatus.UNKNOWN


# Explicit "this account/page does not exist" markers. Checked case-insensitively
# against 2xx responses to catch soft-404s (custom 200-status error pages that
# echo the requested handle back).
GENERIC_MISSING_MARKERS = (
    "user not found",
    "profile not found",
    "account not found",
    "page not found",
    "this page doesn't exist",
    "this page does not exist",
    "page you were looking for doesn't exist",
    "the page you requested cannot be found",
    "sorry, this page isn't available",
    "this page isn't available",
    "no such user",
    "unknown user",
    "does not exist",
    "doesn't exist",
    "couldn't find",
    "could not find",
)


def _has_missing_marker(text: str) -> bool:
    lowered = text.lower()
    return any(m in lowered for m in GENERIC_MISSING_MARKERS)


def decide_generic(status: int, text: str, username: str) -> ClaimStatus:
    """Fallback verifier for sites we have no spec for (used by confirm pass).

    Deliberately strict — the goal is "only report real info":

    * 2xx + the handle actually present in the page -> EXISTS
    * 2xx with an explicit missing marker (soft-404) -> NOT_EXISTS
    * 2xx without either signal (JS shell, JSON API, unrelated page) -> UNKNOWN
    * 404/410 -> NOT_EXISTS, blocked/rate-limited -> UNKNOWN
    """
    if status == 429 or status in _BLOCK_STATUSES:
        return ClaimStatus.UNKNOWN
    if status in (404, 410):
        return ClaimStatus.NOT_EXISTS
    if _waf_hit(text):
        return ClaimStatus.UNKNOWN
    if 300 <= status < 400:
        return ClaimStatus.UNKNOWN
    if 200 <= status < 300:
        if _has_missing_marker(text):
            return ClaimStatus.NOT_EXISTS
        if username and len(username) >= 3 and username.lower() in text.lower():
            return ClaimStatus.EXISTS
        return ClaimStatus.UNKNOWN
    return ClaimStatus.UNKNOWN


# ---------------------------------------------------------------------------
# Database loaders
# ---------------------------------------------------------------------------

@lru_cache(maxsize=2)
def load_sherlock_specs() -> Dict[str, PageSpec]:
    raw = json.loads((DATA_DIR / "sherlock-data.json").read_text(encoding="utf-8"))
    raw.pop("$schema", None)
    specs: Dict[str, PageSpec] = {}
    for name, info in raw.items():
        from ..core.normalize import site_key
        key = site_key(info.get("urlMain") or info.get("url") or name)
        engine = info.get("errorType", "status_code")
        method = (info.get("request_method") or "").upper()
        if not method:
            method = "HEAD" if engine == "status_code" else "GET"
        specs[key] = PageSpec(
            key=key,
            name=name,
            url_user=info.get("url", ""),
            url_probe=info.get("urlProbe"),
            method=method,
            engine=engine if engine in ("status_code", "message", "response_url") else "status_code",
            error_codes=[info["errorCode"]] if isinstance(info.get("errorCode"), int) else info.get("errorCode"),
            error_msgs=info.get("errorMsg") if isinstance(info.get("errorMsg"), list) else ([info["errorMsg"]] if info.get("errorMsg") else None),
            error_url=info.get("errorUrl"),
            regex_check=info.get("regexCheck"),
            headers=info.get("headers") or {},
            request_payload=info.get("request_payload"),
            nsfw=bool(info.get("isNSFW", False)),
        )
    return specs


@lru_cache(maxsize=2)
def load_wmn_specs() -> Dict[str, PageSpec]:
    raw = json.loads((DATA_DIR / "wmn-data.json").read_text(encoding="utf-8"))
    specs: Dict[str, PageSpec] = {}
    for info in raw.get("sites", []):
        from ..core.normalize import site_key
        uri = info.get("uri_check", "")
        key = site_key(uri.replace("{account}", "x"))
        specs[key] = PageSpec(
            key=key,
            name=info.get("name", ""),
            url_user=uri,
            method="GET",
            engine="wmn",
            e_code=info.get("e_code"),
            e_string=info.get("e_string", "") or "",
            m_code=info.get("m_code"),
            m_string=info.get("m_string", "") or "",
            nsfw=info.get("cat") == "xx NSFW xx",
        )
    return specs


def best_spec_for(key: str) -> Optional[PageSpec]:
    """Prefer WhatsMyName specs (string markers beat bare status codes)."""
    wmn = load_wmn_specs().get(key)
    if wmn and (wmn.e_string or wmn.m_string):
        return wmn
    sherlock = load_sherlock_specs().get(key)
    if sherlock:
        return sherlock
    return wmn


def decide(spec: PageSpec, status: int, text: str, final_url: str = "", username: str = "") -> ClaimStatus:
    """Dispatch to the right decision function for this spec's engine."""
    if spec.engine == "wmn":
        return decide_wmn(spec, status, text)
    if spec.engine in ("message", "status_code", "response_url"):
        return decide_sherlock(spec, status, text, final_url, username)
    return decide_generic(status, text, username)
