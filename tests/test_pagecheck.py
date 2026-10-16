"""Pure decision logic for the Sherlock / WhatsMyName / generic page checks."""

import pytest

from ultimate_osint.core.result import ClaimStatus
from ultimate_osint.integrations.pagecheck import (
    PageSpec,
    decide,
    decide_generic,
    decide_sherlock,
    decide_wmn,
    has_search_path,
    interpolate,
    is_interstitial,
    load_sherlock_specs,
    load_wmn_specs,
    looks_like_search,
)


def wmn_spec(**kw):
    base = dict(
        key="example.com",
        name="Example",
        url_user="https://example.com/{}",
        engine="wmn",
        e_code=200,
        e_string="ACCOUNT_OK",
        m_code=404,
        m_string="does not exist",
    )
    base.update(kw)
    return PageSpec(**base)


def sherlock_spec(**kw):
    base = dict(
        key="example.com",
        name="Example",
        url_user="https://example.com/{}",
        engine="status_code",
    )
    base.update(kw)
    return PageSpec(**base)


class TestInterpolate:
    def test_braces_style(self):
        assert interpolate("https://github.com/{}", "user") == "https://github.com/user"

    def test_account_style(self):
        assert interpolate("https://site/{account}", "user") == "https://site/user"

    def test_empty(self):
        assert interpolate("", "user") == ""


class TestWhatsMyName:
    def test_exists_marker_present(self):
        st = decide_wmn(wmn_spec(), 200, "<html>ACCOUNT_OK here</html>")
        assert st == ClaimStatus.EXISTS

    def test_e_code_but_marker_missing_is_unknown(self):
        # e_code matched, but the existence string is absent -> inconclusive
        st = decide_wmn(wmn_spec(), 200, "<html>nothing useful</html>")
        assert st == ClaimStatus.UNKNOWN

    def test_missing_marker_wins(self):
        st = decide_wmn(wmn_spec(), 200, "<html>ACCOUNT_OK but does not exist</html>")
        assert st == ClaimStatus.NOT_EXISTS

    def test_m_code(self):
        assert decide_wmn(wmn_spec(), 404, "") == ClaimStatus.NOT_EXISTS

    def test_rate_limited_never_a_finding(self):
        assert decide_wmn(wmn_spec(), 429, "ACCOUNT_OK") == ClaimStatus.UNKNOWN

    def test_unauthenticated_403_proves_nothing(self):
        spec = wmn_spec(e_code=403, e_string="")
        assert decide_wmn(spec, 403, "") == ClaimStatus.UNKNOWN

    def test_waf_page_is_unknown(self):
        text = 'AwsWafIntegration.forceRefreshToken'
        assert decide_wmn(wmn_spec(), 200, "ACCOUNT_OK " + text) == ClaimStatus.UNKNOWN


class TestSherlock:
    def test_status_code_ok(self):
        spec = sherlock_spec(engine="status_code", error_codes=[404])
        assert decide_sherlock(spec, 200, "") == ClaimStatus.EXISTS
        assert decide_sherlock(spec, 404, "") == ClaimStatus.NOT_EXISTS

    def test_blocked_status_is_unknown(self):
        spec = sherlock_spec(engine="status_code", error_codes=[404])
        assert decide_sherlock(spec, 403, "") == ClaimStatus.UNKNOWN
        assert decide_sherlock(spec, 429, "") == ClaimStatus.UNKNOWN

    def test_message_engine(self):
        spec = sherlock_spec(engine="message", error_msgs=["<title>404 Not Found</title>"])
        assert decide_sherlock(spec, 200, "<html>profile page</html>") == ClaimStatus.EXISTS
        assert decide_sherlock(spec, 200, "<title>404 Not Found</title>") == ClaimStatus.NOT_EXISTS

    def test_message_engine_404_without_marker_is_unknown(self):
        # stricter than upstream: a bare 404 is not proof of "not exists" here
        spec = sherlock_spec(engine="message", error_msgs=["<title>404</title>"])
        assert decide_sherlock(spec, 404, "plain body") == ClaimStatus.UNKNOWN

    def test_response_url_engine(self):
        spec = sherlock_spec(engine="response_url")
        assert decide_sherlock(spec, 200, "") == ClaimStatus.EXISTS
        assert decide_sherlock(spec, 302, "", final_url="https://example.com") == ClaimStatus.NOT_EXISTS

    def test_202_is_not_a_profile(self):
        spec = sherlock_spec(engine="status_code", error_codes=[404])
        assert decide_sherlock(spec, 202, "x") == ClaimStatus.UNKNOWN

    def test_handle_must_appear_in_body(self):
        spec = sherlock_spec(engine="status_code", error_codes=[404])
        assert decide_sherlock(spec, 200, "<h1>user here</h1>", username="user") == ClaimStatus.EXISTS
        assert decide_sherlock(spec, 200, "generic page", username="user") == ClaimStatus.UNKNOWN

    def test_soft_404_marker_wins(self):
        spec = sherlock_spec(engine="status_code", error_codes=[404])
        assert decide_sherlock(spec, 200, "Sorry, this user does not exist", username="user") == ClaimStatus.NOT_EXISTS


class TestInterstitial:
    def test_consent_domain(self):
        assert is_interstitial("https://consent.youtube.com/m?x", "https://www.youtube.com/@u")

    def test_cross_domain_redirect(self):
        assert is_interstitial("https://www.threads.com/@u", "https://www.threads.net/@u")

    def test_wall_path(self):
        assert is_interstitial(
            "https://discussions.apple.com/verify-human/verify.html",
            "https://discussions.apple.com/profile/u",
        )

    def test_apex_to_www_is_fine(self):
        assert not is_interstitial("https://www.example.com/u", "https://example.com/u")

    def test_plain_page_is_fine(self):
        assert not is_interstitial("https://github.com/user", "https://github.com/user")


class TestSearchUrl:
    def test_search_pages_detected(self):
        assert looks_like_search("https://www.vinted.pt/member/general/search?search_text=x")
        assert looks_like_search("https://stackoverflow.com/users/filter?search=x")

    def test_profile_pages_pass(self):
        assert not looks_like_search("https://github.com/user")
        assert not looks_like_search("")

    def test_handle_in_query_is_a_lookup(self):
        assert looks_like_search("https://forum.velomania.ru/member.php?username=darkcurl.test.2026", "darkcurl.test.2026")

    def test_search_path_only(self):
        assert has_search_path("https://sepiasearch.org/api/v1/search/video-channels?search=x")
        assert has_search_path("https://mynickname.com/en/search?q=x")
        # a query-param lookup API is NOT a search path
        assert not has_search_path("https://www.habbo.de/api/public/users?name=x")
        assert not has_search_path("https://github.com/user")

class TestGeneric:
    def test_404_is_not_exists(self):
        assert decide_generic(404, "", "user") == ClaimStatus.NOT_EXISTS
        assert decide_generic(410, "", "user") == ClaimStatus.NOT_EXISTS

    def test_handle_present_is_exists(self):
        assert decide_generic(200, "<h1>user's profile</h1>", "user") == ClaimStatus.EXISTS

    def test_big_page_without_handle_is_unknown(self):
        # the old "len(text) > 500 -> exists" heuristic was a false-positive farm
        assert decide_generic(200, "x" * 5000, "user") == ClaimStatus.UNKNOWN

    def test_soft_404_markers(self):
        assert decide_generic(200, "Sorry, this page isn't available", "user") == ClaimStatus.NOT_EXISTS
        assert decide_generic(200, "This user does not exist", "user") == ClaimStatus.NOT_EXISTS

    def test_blocked_and_rate_limited(self):
        assert decide_generic(403, "", "user") == ClaimStatus.UNKNOWN
        assert decide_generic(429, "", "user") == ClaimStatus.UNKNOWN

    def test_dispatch(self):
        assert decide(wmn_spec(), 200, "ACCOUNT_OK") == ClaimStatus.EXISTS
        assert decide(sherlock_spec(error_codes=[404]), 404, "") == ClaimStatus.NOT_EXISTS
        assert decide(sherlock_spec(engine="unknown-engine"), 404, "", "", "user") == ClaimStatus.NOT_EXISTS


class TestDatabases:
    def test_sherlock_db_loads(self):
        specs = load_sherlock_specs()
        assert len(specs) > 300
        assert "github.com" in specs

    def test_wmn_db_loads(self):
        specs = load_wmn_specs()
        assert len(specs) > 500
        assert "github.com" in specs
        assert any(s.e_string or s.m_string for s in specs.values())

    def test_databases_are_cached(self):
        assert load_sherlock_specs() is load_sherlock_specs()
        assert load_wmn_specs() is load_wmn_specs()
