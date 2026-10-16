"""Site-identity normalization: the glue that lets tools' results merge."""

from ultimate_osint.core.normalize import (
    email_domain,
    email_local_part,
    is_email,
    is_username,
    registrable_domain,
    site_key,
    site_match,
)


class TestRegistrableDomain:
    def test_plain(self):
        assert registrable_domain("github.com") == "github.com"

    def test_www_stripped(self):
        assert registrable_domain("www.github.com") == "github.com"

    def test_subdomain_kept_to_etld1(self):
        assert registrable_domain("gist.github.com") == "github.com"
        assert registrable_domain("en.wikipedia.org") == "wikipedia.org"

    def test_mobile_prefix(self):
        assert registrable_domain("mobile.twitter.com") == "twitter.com"
        assert registrable_domain("m.facebook.com") == "facebook.com"

    def test_multi_part_suffix(self):
        assert registrable_domain("foo.co.uk") == "foo.co.uk"
        assert registrable_domain("sub.foo.com.au") == "foo.com.au"

    def test_empty(self):
        assert registrable_domain("") == ""


class TestSiteKey:
    def test_url_twitter_collapses_to_x(self):
        assert site_key("https://twitter.com/someuser") == "x.com"
        assert site_key("https://mobile.twitter.com/someuser") == "x.com"
        assert site_key("https://x.com/someuser") == "x.com"

    def test_bare_names(self):
        assert site_key("Twitter") == "x.com"
        assert site_key("GitHub") == "github.com"
        assert site_key("Reddit") == "reddit.com"

    def test_reddit_variants(self):
        assert site_key("https://www.reddit.com/user/x") == "reddit.com"
        assert site_key("https://old.reddit.com/user/x") == "reddit.com"

    def test_gist_and_github_merge(self):
        assert site_key("https://gist.github.com/u") == site_key("https://github.com/u")

    def test_two_letter_names(self):
        assert site_key("x") == "x.com"

    def test_unknown_name_stays_stable(self):
        assert site_key("Some Forum (EU)") == "someforumeu"


class TestSiteMatch:
    WANTED = {"github.com", "reddit"}

    def test_domain_matches_url(self):
        assert site_match("GitHub (User)", "https://gist.github.com/u", self.WANTED)

    def test_bare_name_matches(self):
        assert site_match("Reddit", "https://reddit.com/u", self.WANTED)

    def test_site_key_of_name(self):
        # entry github.com matches name-only rows (maigret)
        assert site_match("GitHub", "", self.WANTED)

    def test_reject(self):
        assert not site_match("Pinterest", "https://pinterest.com/u", self.WANTED)

    def test_empty_wanted_passes_everything(self):
        assert site_match("Anything", "https://whatever.example", set())


class TestEmailHelpers:
    def test_split(self):
        assert email_local_part("a.b@example.com") == "a.b"
        assert email_domain("a.b@example.com") == "example.com"

    def test_validation(self):
        assert is_email("user@example.com")
        assert not is_email("not-an-email")
        assert is_username("some_user")
        assert not is_email("some_user")
