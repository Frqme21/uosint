"""Unified result model shared by every source and the confirmation pass."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional


class ClaimStatus(Enum):
    """Raw outcome reported by a source before cross-referencing."""

    EXISTS = "exists"
    NOT_EXISTS = "not_exists"
    UNKNOWN = "unknown"  # rate limit / blocked / network error -> NOT a finding
    SKIPPED = "skipped"  # invalid for this site, filtered out, etc.


class Verdict(Enum):
    """Final verdict after cross-referencing + direct verification."""

    CONFIRMED = "confirmed"  # proof (metadata/signup API) or live re-check passed + consensus/marker
    LIKELY = "likely"  # single source / inconclusive re-check, but not contradicted
    REFUTED = "refuted"  # direct verification contradicted the claim (hidden by default)
    UNVERIFIED = "unverified"  # claimed but could not be verified (hidden by default)

    @property
    def is_positive(self) -> bool:
        return self in (Verdict.CONFIRMED, Verdict.LIKELY)


# Sources whose detection method queries the target's own backend (API / signup
# endpoint / password-reset flow) rather than scraping page content. A *bare*
# claim from these still gets re-verified; only metadata or an API answer is proof.
HIGH_TRUST_SOURCES = {"socialscan", "darkcurl", "holehe", "hudson", "emailrep", "hibp"}

# Sources that rely on page heuristics and therefore benefit from verification
# or multi-source consensus.
PAGE_HEURISTIC_SOURCES = {"maigret", "sherlock", "wmn"}


@dataclass
class UnifiedResult:
    """One source's claim about one site for one target."""

    target: str
    target_type: str  # "username" | "email"
    source: str  # darkcurl, maigret, sherlock, wmn, holehe, socialscan, ...
    site: str  # human readable site name as reported by the source
    url: str  # profile / evidence URL
    status: ClaimStatus
    confidence: float = 0.5  # per-source self confidence
    method: str = ""  # e.g. "status_code", "page_markers", "signup_api"
    extra: Dict[str, Any] = field(default_factory=dict)
    reason: str = ""

    # Filled in by the cross-reference + confirmation pass
    site_key: str = ""  # normalized key (registrable domain) used for merging
    verdict: Optional[Verdict] = None
    verdict_reason: str = ""
    consensus: int = 1  # how many independent sources claimed this site
    evidence: Dict[str, Any] = field(default_factory=dict)

    @property
    def exists(self) -> bool:
        return self.status == ClaimStatus.EXISTS

    @property
    def rich_evidence(self) -> bool:
        """True when the source extracted real profile metadata (not just a 200)."""
        return bool(self.extra) and bool(self.url)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "target": self.target,
            "target_type": self.target_type,
            "source": self.source,
            "site": self.site,
            "site_key": self.site_key,
            "url": self.url,
            "status": self.status.value,
            "method": self.method,
            "confidence": self.confidence,
            "verdict": self.verdict.value if self.verdict else None,
            "verdict_reason": self.verdict_reason,
            "consensus": self.consensus,
            "extra": self.extra,
            "evidence": self.evidence,
            "reason": self.reason,
        }


@dataclass
class SourceSummary:
    """Per-source run statistics for the report."""

    name: str
    checked: int = 0
    found: int = 0
    errors: int = 0
    skipped: int = 0
    seconds: float = 0.0
    available: bool = True
    note: str = ""

    @property
    def degraded(self) -> bool:
        """More than half the checks failed -> likely rate-limited or blocked."""
        return self.available and self.checked > 10 and self.errors > self.checked * 0.5

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "checked": self.checked,
            "found": self.found,
            "errors": self.errors,
            "skipped": self.skipped,
            "seconds": round(self.seconds, 2),
            "available": self.available,
            "note": self.note,
        }


@dataclass
class ScanReport:
    target: str
    target_type: str
    results: List[UnifiedResult] = field(default_factory=list)
    summaries: List[SourceSummary] = field(default_factory=list)
    pivots: List[str] = field(default_factory=list)
    intel: List[Dict[str, Any]] = field(default_factory=list)  # breach/reputation blocks

    @property
    def confirmed(self) -> List[UnifiedResult]:
        return [r for r in self.results if r.verdict == Verdict.CONFIRMED and r.exists]

    @property
    def likely(self) -> List[UnifiedResult]:
        return [r for r in self.results if r.verdict == Verdict.LIKELY and r.exists]

    @property
    def refuted(self) -> List[UnifiedResult]:
        return [r for r in self.results if r.verdict == Verdict.REFUTED]

    @property
    def unverified(self) -> List[UnifiedResult]:
        return [r for r in self.results if r.verdict == Verdict.UNVERIFIED and r.exists]
