"""Report rendering + export shape."""

import csv
import io
import json

from ultimate_osint.core.report import _best_url, _source_badges, into_csv, into_json
from ultimate_osint.core.result import (
    ClaimStatus,
    ScanReport,
    SourceSummary,
    UnifiedResult,
    Verdict,
)


def claim(source, site, url, verdict=Verdict.CONFIRMED, extra=None, consensus=1, key=None):
    r = UnifiedResult(
        target="user",
        target_type="username",
        source=source,
        site=site,
        url=url,
        status=ClaimStatus.EXISTS,
        extra=extra or {},
    )
    r.site_key = key or "example.com"
    r.verdict = verdict
    r.verdict_reason = "test reason"
    r.consensus = consensus
    return r


def sample_report():
    report = ScanReport(target="user", target_type="username")
    report.results = [
        claim("darkcurl", "GitHub", "https://gist.github.com/user", extra={"id": 1}, consensus=4),
        claim("maigret", "GitHub", "https://github.com/user", consensus=4),
        claim("sherlock", "GitHub", "https://github.com/user", consensus=4),
        claim("wmn", "GitHub", "https://github.com/user", consensus=4),
        claim("sherlock", "Example", "https://example.com/user", verdict=Verdict.LIKELY),
        claim("sherlock", "Dead", "https://dead.example/u", verdict=Verdict.REFUTED),
    ]
    report.summaries = [
        SourceSummary(name="darkcurl", checked=192, found=68, errors=33, seconds=10.4),
        SourceSummary(name="hudson", available=False, note="opt-in only"),
    ]
    report.intel = [{"source": "dns", "domain": "example.com", "records": {"mx": ["mx.example.com"]}}]
    report.pivots = ["otherhandle"]
    return report


class TestBestUrl:
    def test_consensus_url_wins(self):
        claims = [
            claim("darkcurl", "GitHub", "https://gist.github.com/user", extra={"id": 1}),
            claim("maigret", "GitHub", "https://github.com/user"),
            claim("sherlock", "GitHub", "https://github.com/user"),
        ]
        assert _best_url(claims) == "https://github.com/user"

    def test_trailing_slash_ignored(self):
        claims = [
            claim("a", "X", "https://x.com/u/"),
            claim("b", "X", "https://x.com/u"),
        ]
        assert _best_url(claims) == "https://x.com/u/"

    def test_empty(self):
        assert _best_url([claim("a", "X", "")]) == ""


class TestSourceBadges:
    def test_sorted_unique(self):
        assert _source_badges([claim("wmn", "x", ""), claim("darkcurl", "x", "")]) == "darkcurl, wmn"


class TestJsonExport:
    def test_shape(self):
        data = json.loads(into_json(sample_report()))
        assert data["target"] == "user"
        assert data["stats"]["confirmed"] == 4
        assert data["stats"]["likely"] == 1
        assert data["stats"]["refuted"] == 1
        assert len(data["results"]) == 6
        assert data["pivots"] == ["otherhandle"]
        assert any(s["name"] == "darkcurl" for s in data["sources"])
        assert data["intel"][0]["source"] == "dns"
        # every result carries its verdict + consensus
        assert all("verdict" in r and "consensus" in r for r in data["results"])


class TestCsvExport:
    def test_rows_grouped_by_site(self):
        rows = list(csv.reader(io.StringIO(into_csv(sample_report()))))
        header, body = rows[0], rows[1:]
        assert header == [
            "target", "site", "site_key", "url", "verdict", "consensus", "sources", "method", "extra", "reason",
        ]
        by_key = {r[2]: r for r in body}
        assert "example.com" in by_key
        # the 4 GitHub claims collapse into one CSV row with the consensus URL
        github = next(r for r in body if r[3] == "https://github.com/user")
        assert github[5] == "4"
        assert github[6] == "darkcurl;maigret;sherlock;wmn"
