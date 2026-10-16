"""Cross-referencing + direct verification: turn raw source claims into verdicts.

Strategy
--------
1. Merge claims from all tools by registrable domain (Twitter/X collapse into one).
2. Count independent sources per site (consensus).
3. Claims that come with extracted profile metadata or from signup/API answers are proof.
4. Everything else gets re-verified live against the best available spec
   (WhatsMyName string markers > Sherlock errorType > generic heuristics), with
   guards against soft-404s, consent/interstitial redirects and lookup/search URLs.
5. Verdicts: CONFIRMED / LIKELY / REFUTED / UNVERIFIED — only confirmed+likely
   are shown as findings. Consensus only confirms when the live page corroborates;
   otherwise it is downgraded to LIKELY.
"""

from __future__ import annotations

import asyncio
import time
from typing import Dict, List, Optional, Tuple
from urllib.parse import quote

import httpx

from .normalize import display_name, site_key
from .result import (
    HIGH_TRUST_SOURCES,
    PAGE_HEURISTIC_SOURCES,
    ClaimStatus,
    UnifiedResult,
    Verdict,
)
from ..integrations.pagecheck import (
    best_spec_for,
    decide,
    decide_generic,
    has_search_path,
    interpolate,
    is_interstitial,
    looks_like_search,
)

UA = "Mozilla/5.0 (X11; Linux x86_64; rv:129.0) Gecko/20100101 Firefox/129.0"

# Signup-API based: the site itself answers "is this taken?" -> self-verifying.
PROOF_SOURCES = {"socialscan"}
# Sources that query the target's own backend (password-reset / status APIs).
API_SOURCES = {"holehe", "emailrep", "hibp"}
# Sources that scrape a real profile page and can therefore return metadata.
RICH_EVIDENCE_SOURCES = {"darkcurl", "holehe"}
# Reliable-but-not-proof: worth confirming on their word when a live page agrees.
SEMI_TRUSTED_SOURCES = {"darkcurl", "socialscan"}


class _Verdict:
    __slots__ = ("verdict", "reason", "evidence")

    def __init__(self, verdict: Verdict, reason: str, evidence: Optional[dict] = None):
        self.verdict = verdict
        self.reason = reason
        self.evidence = evidence or {}


async def _verify_key(
    key: str,
    claims: List[UnifiedResult],
    client: httpx.AsyncClient,
    sem: asyncio.Semaphore,
    timeout: float,
) -> Tuple[Verdict, str, dict]:
    """Re-check a merged site claim live. Returns (verdict, reason, evidence).

    Precision rules (see the module docstring): a claim only reaches verdict
    logic here when it has no metadata/signup proof, so the live re-check plus
    independent-source consensus are what decide whether it is real.
    """
    consensus = len({c.source for c in claims})
    high_trust = any(c.source in HIGH_TRUST_SOURCES for c in claims)
    semi_trusted = any(c.source in SEMI_TRUSTED_SOURCES for c in claims)

    # Pick the best URL / display evidence to verify
    url = next((c.url for c in claims if c.url), "")
    target = claims[0].target

    spec = best_spec_for(key)

    async with sem:
        if spec:
            quoted = quote(target, safe="")
            probe = interpolate(spec.url_probe or spec.url_user, quoted)
            if not probe:
                return Verdict.UNVERIFIED, "spec has no probe URL", {}
            headers = {"User-Agent": UA}
            headers.update(spec.headers or {})
            try:
                follow = spec.engine != "response_url"
                if spec.method.upper() == "HEAD":
                    resp = await client.head(probe, headers=headers, follow_redirects=follow)
                else:
                    resp = await client.get(probe, headers=headers, follow_redirects=follow)
                status_code = resp.status_code
                text = ""
                if status_code == 200 or spec.engine != "status_code":
                    try:
                        text = resp.text[:600_000]
                    except Exception:
                        text = ""
            except Exception as e:
                if consensus >= 2:
                    return Verdict.LIKELY, f"{consensus} sources agree (re-check failed: {type(e).__name__})", {}
                return Verdict.UNVERIFIED, f"re-check failed: {type(e).__name__}", {}

            outcome = decide(spec, status_code, text, final_url=str(resp.url), username=target)
            bounced = is_interstitial(str(resp.url), probe)
            if bounced:
                outcome = ClaimStatus.UNKNOWN
            # A handle echoed back from a search endpoint or a lookup URL is not
            # proof of a profile unless the spec has an explicit content marker.
            if outcome == ClaimStatus.EXISTS and has_search_path(probe):
                outcome = ClaimStatus.UNKNOWN
            elif outcome == ClaimStatus.EXISTS and not spec.e_string and looks_like_search(probe, target):
                outcome = ClaimStatus.UNKNOWN

            # A spec that carries explicit content markers (e_string / m_string)
            # is a stronger signal than a bare status-code or absence check.
            content_bound = bool(spec.e_string or spec.m_string)

            evidence = {
                "engine": spec.engine,
                "http_status": status_code,
                "probe": probe,
                "spec": spec.name,
                "content_marker": content_bound,
            }
            if bounced:
                evidence["bounced_to"] = str(resp.url)

            if outcome == ClaimStatus.EXISTS:
                if consensus >= 2:
                    return Verdict.CONFIRMED, f"{consensus} sources agree + live re-check passed", evidence
                if content_bound or semi_trusted:
                    return Verdict.CONFIRMED, f"live re-check passed ({spec.engine} markers)", evidence
                return Verdict.LIKELY, "live re-check passed, single weak source", evidence
            if outcome == ClaimStatus.UNKNOWN:
                if consensus >= 2:
                    return Verdict.LIKELY, f"{consensus} sources agree (re-check inconclusive)", evidence
                if semi_trusted:
                    return Verdict.LIKELY, "API-level source, but re-check inconclusive", evidence
                return Verdict.UNVERIFIED, "re-check inconclusive (blocked or rate limited)", evidence
            # NOT_EXISTS
            if consensus >= 2:
                return Verdict.UNVERIFIED, f"CONFLICT: {consensus} sources claim exists, live check says missing", evidence
            if claims[0].source in HIGH_TRUST_SOURCES:
                return Verdict.UNVERIFIED, "CONFLICT: source reports API-level finding, live page check says missing", evidence
            return Verdict.REFUTED, "live re-check contradicts claim", evidence

        # ---- generic verification (no spec for this site) ----
        if not url:
            if consensus >= 2:
                return Verdict.LIKELY, f"{consensus} sources agree (no URL to verify)", {}
            if high_trust:
                return Verdict.LIKELY, "API-level source, no URL to verify", {}
            return Verdict.UNVERIFIED, "no URL to verify", {}

        # A search/query endpoint can mention a handle without the handle owning
        # an account there -> never treat it as confirmation.
        if looks_like_search(url, target):
            if consensus >= 2:
                return Verdict.LIKELY, f"{consensus} sources agree (only a search URL found)", {}
            return Verdict.UNVERIFIED, "claim URL is a search/query page, not a profile", {}

        try:
            resp = await client.get(url, headers={"User-Agent": UA}, follow_redirects=True)
            status_code = resp.status_code
            try:
                text = resp.text[:600_000]
            except Exception:
                text = ""
        except Exception as e:
            if consensus >= 2:
                return Verdict.LIKELY, f"{consensus} sources agree (re-check failed: {type(e).__name__})", {}
            return Verdict.UNVERIFIED, f"re-check failed: {type(e).__name__}", {}

        outcome = decide_generic(status_code, text, target)
        if is_interstitial(str(resp.url), url):
            outcome = ClaimStatus.UNKNOWN
        evidence = {"engine": "generic", "http_status": status_code, "probe": url}

        if outcome == ClaimStatus.EXISTS:
            # decide_generic only returns EXISTS when the handle is visible in
            # the page body, so this is independent corroboration.
            if consensus >= 2 or semi_trusted:
                return Verdict.CONFIRMED, "live page shows the handle", evidence
            return Verdict.LIKELY, "single source, handle seen on live page", evidence
        if outcome == ClaimStatus.UNKNOWN:
            if consensus >= 2:
                return Verdict.LIKELY, f"{consensus} sources agree (re-check inconclusive)", evidence
            if semi_trusted:
                return Verdict.LIKELY, "API-level source, but re-check inconclusive", evidence
            return Verdict.UNVERIFIED, "re-check inconclusive", evidence
        # NOT_EXISTS
        if consensus >= 2:
            return Verdict.UNVERIFIED, f"CONFLICT: {consensus} sources claim exists, live check says missing", evidence
        if claims[0].source in PAGE_HEURISTIC_SOURCES:
            return Verdict.REFUTED, "live re-check contradicts claim", evidence
        return Verdict.UNVERIFIED, "CONFLICT: source reports finding, live check says missing", evidence


async def confirm_all(results: List[UnifiedResult], cfg) -> List[UnifiedResult]:
    """Assign a verdict to every claim and return them (deduped display order)."""
    # 1. normalize keys
    for r in results:
        if not r.site_key:
            r.site_key = site_key(r.url or r.site)

    # 2. group positive claims by key
    groups: Dict[str, List[UnifiedResult]] = {}
    for r in results:
        if r.status == ClaimStatus.EXISTS:
            groups.setdefault(r.site_key or r.site.lower(), []).append(r)

    # 3. proof-based verdicts (no network needed)
    to_verify: Dict[str, List[UnifiedResult]] = {}
    pre: Dict[str, _Verdict] = {}
    for key, claims in groups.items():
        if any(c.source in PROOF_SOURCES for c in claims):
            pre[key] = _Verdict(Verdict.CONFIRMED, "verified against signup API")
        elif any(c.source in RICH_EVIDENCE_SOURCES and c.extra for c in claims):
            proof = next(c for c in claims if c.source in RICH_EVIDENCE_SOURCES and c.extra)
            pre[key] = _Verdict(
                Verdict.CONFIRMED,
                "profile metadata extracted from live page",
                {"extracted": dict(list(proof.extra.items())[:8])},
            )
        elif any(c.source in API_SOURCES for c in claims):
            pre[key] = _Verdict(Verdict.CONFIRMED, "queries the site's own backend")
        else:
            to_verify[key] = claims

    # 4. live verification for the rest
    if to_verify:
        sem = asyncio.Semaphore(40)
        async with httpx.AsyncClient(timeout=cfg.timeout) as client:
            tasks = {
                key: asyncio.create_task(_verify_key(key, claims, client, sem, cfg.timeout))
                for key, claims in to_verify.items()
            }
            for key, task in tasks.items():
                verdict, reason, evidence = await task
                pre[key] = _Verdict(verdict, reason, evidence)

    # 5. write verdicts back onto every claim (including not-exists stats rows)
    consensus_by_key = {
        key: len({c.source for c in claims}) for key, claims in groups.items()
    }
    for r in results:
        key = r.site_key or r.site.lower()
        if r.status != ClaimStatus.EXISTS:
            r.verdict = None
            continue
        v = pre.get(key)
        if not v:
            r.verdict = Verdict.UNVERIFIED
            r.verdict_reason = "no verdict computed"
            continue
        r.verdict = v.verdict
        r.verdict_reason = v.reason
        r.consensus = consensus_by_key.get(key, 1)
        if v.evidence:
            r.evidence = dict(v.evidence)

    return results


def merged_display(results: List[UnifiedResult]) -> List[Tuple[str, str, List[UnifiedResult]]]:
    """Group confirmed/likely claims by site_key for the report."""
    groups: Dict[str, List[UnifiedResult]] = {}
    for r in results:
        if r.status == ClaimStatus.EXISTS and r.verdict and r.verdict.is_positive:
            groups.setdefault(r.site_key or r.site.lower(), []).append(r)

    rows = []
    for key, claims in groups.items():
        name = display_name(
            *(c.site for c in claims if c.extra),
            *(c.site for c in claims),
        )
        rows.append((key, name, claims))
    return rows
