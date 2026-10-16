"""Verdict matrix of the cross-reference / confirmation engine.

Network is faked so the decision logic itself is what gets tested.
"""

import asyncio

import pytest

from ultimate_osint.core import confirm as confirm_mod
from ultimate_osint.core.confirm import confirm_all, merged_display
from ultimate_osint.core.orchestrator import UltimateConfig, _discover_pivots
from ultimate_osint.core.result import ClaimStatus, ScanReport, UnifiedResult, Verdict
from ultimate_osint.integrations.pagecheck import PageSpec


# ---------------------------------------------------------------------------
# fakes
# ---------------------------------------------------------------------------

class FakeResponse:
    def __init__(self, status_code, text="", url="https://example.com/u"):
        self.status_code = status_code
        self.text = text
        self.url = url


class FakeClient:
    """Returns a canned response per call (ignores the URL)."""

    def __init__(self, status_code=200, text=""):
        self.status_code = status_code
        self.text = text

    async def get(self, url, **kwargs):
        return FakeResponse(self.status_code, self.text, url)

    async def head(self, url, **kwargs):
        return FakeResponse(self.status_code, self.text, url)


def claim(source, site, url, extra=None, status=ClaimStatus.EXISTS, target="user", method="", key=None):
    from ultimate_osint.core.normalize import site_key as _site_key

    r = UnifiedResult(
        target=target,
        target_type="username",
        source=source,
        site=site,
        url=url,
        status=status,
        method=method,
        extra=extra or {},
    )
    r.site_key = key or _site_key(url or site)
    return r


def run_verify(claims, client, spec=None, monkeypatch=None):
    monkeypatch.setattr(confirm_mod, "best_spec_for", lambda key: spec)
    sem = asyncio.Semaphore(2)
    return asyncio.run(confirm_mod._verify_key("example.com", claims, client, sem, 5.0))


# ---------------------------------------------------------------------------
# spec-based verification
# ---------------------------------------------------------------------------

SPEC = PageSpec(
    key="example.com",
    name="Example",
    url_user="https://example.com/{}",
    engine="wmn",
    e_code=200,
    e_string="ACCOUNT_OK",
    m_code=404,
    m_string="does not exist",
)


class TestSpecVerification:
    def test_marker_pass_confirms(self, monkeypatch):
        verdict, reason, ev = run_verify(
            [claim("maigret", "Example", "https://example.com/user")],
            FakeClient(200, "ACCOUNT_OK"),
            SPEC,
            monkeypatch,
        )
        assert verdict == Verdict.CONFIRMED
        assert ev["engine"] == "wmn"

    def test_refutation_single_source(self, monkeypatch):
        verdict, reason, _ = run_verify(
            [claim("maigret", "Example", "https://example.com/user")],
            FakeClient(404, ""),
            SPEC,
            monkeypatch,
        )
        assert verdict == Verdict.REFUTED

    def test_refutation_with_consensus_becomes_unverified(self, monkeypatch):
        verdict, reason, _ = run_verify(
            [
                claim("maigret", "Example", "https://example.com/user"),
                claim("sherlock", "Example", "https://example.com/user"),
            ],
            FakeClient(404, ""),
            SPEC,
            monkeypatch,
        )
        assert verdict == Verdict.UNVERIFIED
        assert "CONFLICT" in reason

    def test_inconclusive_single_source(self, monkeypatch):
        verdict, _, _ = run_verify(
            [claim("maigret", "Example", "https://example.com/user")],
            FakeClient(429, ""),
            SPEC,
            monkeypatch,
        )
        assert verdict == Verdict.UNVERIFIED

    def test_inconclusive_with_consensus_is_likely(self, monkeypatch):
        # agreement without a corroborating live page is only "likely"
        verdict, _, _ = run_verify(
            [
                claim("maigret", "Example", "https://example.com/user"),
                claim("wmn", "Example", "https://example.com/user"),
            ],
            FakeClient(429, ""),
            SPEC,
            monkeypatch,
        )
        assert verdict == Verdict.LIKELY

    def test_status_only_single_source_is_likely(self, monkeypatch):
        status_spec = PageSpec(
            key="example.com",
            name="Example",
            url_user="https://example.com/{}",
            engine="status_code",
            error_codes=[404],
        )
        verdict, _, _ = run_verify(
            [claim("sherlock", "Example", "https://example.com/user")],
            FakeClient(200, "<h1>user</h1>"),
            status_spec,
            monkeypatch,
        )
        assert verdict == Verdict.LIKELY

    def test_bounced_to_consent_page_is_not_confirmed(self, monkeypatch):
        class BounceClient(FakeClient):
            async def get(self, url, **kwargs):
                return FakeResponse(200, self.text, "https://consent.example.com/m?continue=x")

        verdict, reason, _ = run_verify(
            [
                claim("darkcurl", "Example", "https://example.com/user"),
                claim("sherlock", "Example", "https://example.com/user"),
            ],
            BounceClient(200, "ACCOUNT_OK"),
            SPEC,
            monkeypatch,
        )
        assert verdict == Verdict.LIKELY
        assert "inconclusive" in reason


# ---------------------------------------------------------------------------
# generic (no spec) verification
# ---------------------------------------------------------------------------

class TestGenericVerification:
    def test_handle_on_page_single_page_source_is_likely(self, monkeypatch):
        verdict, _, _ = run_verify(
            [claim("sherlock", "Example", "https://example.com/user")],
            FakeClient(200, "<h1>user</h1>"),
            None,
            monkeypatch,
        )
        assert verdict == Verdict.LIKELY

    def test_handle_on_page_api_source_confirms(self, monkeypatch):
        verdict, _, _ = run_verify(
            [claim("darkcurl", "Example", "https://example.com/user")],
            FakeClient(200, "<h1>user</h1>"),
            None,
            monkeypatch,
        )
        assert verdict == Verdict.CONFIRMED

    def test_no_handle_api_source_is_likely(self, monkeypatch):
        # darkcurl claim, page renders nothing verifiable -> honest "likely"
        verdict, _, _ = run_verify(
            [claim("darkcurl", "Example", "https://example.com/user")],
            FakeClient(200, "some unrelated page content"),
            None,
            monkeypatch,
        )
        assert verdict == Verdict.LIKELY

    def test_no_handle_page_source_is_unverified(self, monkeypatch):
        verdict, _, _ = run_verify(
            [claim("wmn", "Example", "https://example.com/user")],
            FakeClient(200, "some unrelated page content"),
            None,
            monkeypatch,
        )
        assert verdict == Verdict.UNVERIFIED

    def test_404_refutes_page_source(self, monkeypatch):
        verdict, _, _ = run_verify(
            [claim("sherlock", "Example", "https://example.com/user")],
            FakeClient(404, ""),
            None,
            monkeypatch,
        )
        assert verdict == Verdict.REFUTED

    def test_404_with_consensus_is_unverified(self, monkeypatch):
        verdict, _, _ = run_verify(
            [
                claim("sherlock", "Example", "https://example.com/user"),
                claim("wmn", "Example", "https://example.com/user"),
            ],
            FakeClient(404, ""),
            None,
            monkeypatch,
        )
        assert verdict == Verdict.UNVERIFIED


# ---------------------------------------------------------------------------
# confirm_all: proof shortcuts + verdict write-back
# ---------------------------------------------------------------------------

class TestConfirmAll:
    def test_proof_sources_skip_network(self, monkeypatch):
        calls = []

        async def fake_verify(key, claims, client, sem, timeout):
            calls.append(key)
            return Verdict.UNVERIFIED, "should not run", {}

        monkeypatch.setattr(confirm_mod, "_verify_key", fake_verify)

        results = [
            claim("socialscan", "Example", "https://example.com/u", method="signup_api"),
            claim("darkcurl", "Other", "https://other.com/u", extra={"id": 1}),
        ]
        out = asyncio.run(confirm_all(results, UltimateConfig()))
        assert calls == []  # neither needed re-verification
        assert all(r.verdict == Verdict.CONFIRMED for r in out)

    def test_verdicts_and_consensus_written_back(self, monkeypatch):
        async def fake_verify(key, claims, client, sem, timeout):
            return Verdict.CONFIRMED, "agreed", {"engine": "test"}

        monkeypatch.setattr(confirm_mod, "_verify_key", fake_verify)

        results = [
            claim("maigret", "Example", "https://example.com/u"),
            claim("sherlock", "Example", "https://example.com/u"),
            claim("wmn", "Example", "https://example.com/u"),
        ]
        out = asyncio.run(confirm_all(results, UltimateConfig()))
        assert all(r.verdict == Verdict.CONFIRMED for r in out)
        assert all(r.consensus == 3 for r in out)
        assert all(r.evidence.get("engine") == "test" for r in out)

    def test_negative_claims_keep_no_verdict(self, monkeypatch):
        monkeypatch.setattr(confirm_mod, "best_spec_for", lambda key: None)
        results = [
            claim("darkcurl", "Example", "", status=ClaimStatus.NOT_EXISTS),
            claim("darkcurl", "Example2", "", status=ClaimStatus.UNKNOWN),
        ]
        out = asyncio.run(confirm_all(results, UltimateConfig()))
        assert all(r.verdict is None for r in out)

    def test_merged_display_groups_only_positive(self, monkeypatch):
        monkeypatch.setattr(confirm_mod, "best_spec_for", lambda key: None)
        a = claim("darkcurl", "Example", "https://example.com/u", extra={"id": 1})
        b = claim("maigret", "Example", "https://example.com/u")
        c = claim("sherlock", "Dead", "https://dead.example/u")
        for r in (a, b):
            r.verdict = Verdict.CONFIRMED
            r.consensus = 2
        c.verdict = Verdict.REFUTED
        rows = merged_display([a, b, c])
        assert len(rows) == 1
        key, name, claims = rows[0]
        assert key == "example.com"
        assert len(claims) == 2


# ---------------------------------------------------------------------------
# pivots
# ---------------------------------------------------------------------------

class TestPivots:
    def test_discovers_localpart_and_usernames(self):
        report = ScanReport(target="someone@example.com", target_type="email")
        report.results.append(
            claim(
                "darkcurl",
                "Steam",
                "https://steamcommunity.com/id/gaben_the_second",
                extra={"username": "gaben_the_second"},
                target="someone@example.com",
            )
        )
        pivots = _discover_pivots("someone@example.com", report)
        assert "someone" in pivots
        assert "gaben_the_second" in pivots

    def test_drops_noise(self):
        report = ScanReport(target="abc@example.com", target_type="email")
        report.results.append(
            claim("darkcurl", "X", "https://x.com/u", extra={"username": "test"}, target="abc@example.com")
        )
        assert _discover_pivots("abc@example.com", report) == ["abc"]
