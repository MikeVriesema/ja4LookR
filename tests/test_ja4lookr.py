"""Tests for ja4lookr — no network; a synthetic DB is injected directly."""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from ja4lookr import (  # noqa: E402
    JA4Lookup, parse_ja4, assess_risk, wildcard_to_regex, defang,
    yara_rule_for,
)

# Reference fingerprints from the FoxIO threat-hunting slides.
CHROME = "t13d1516h2_8daaf6152771_d8a2da3f94cd"
SLIVER = "t13i190800_9dc949149365_97f8aa674fd9"
COBALT = "t12d210600_b973bfd88a0e_1da50ec048a3"
METASPLOIT = "t12i190700_d83cc789557e_16bbda4055b2"

RECORDS = [
    {"ja4_fingerprint": CHROME, "application": "Chrome",
     "user_agent_string": "Mozilla/5.0 Chrome/137", "verified": True},
    # Same ja4_a + ja4_c as Chrome, different cipher hash (b) -> cipher_variant.
    {"ja4_fingerprint": "t13d1516h2_ffffffffffff_d8a2da3f94cd",
     "application": "Chrome Nightly", "verified": False},
    {"ja4_fingerprint": SLIVER, "application": "Sliver", "verified": False},
    {"ja4_fingerprint": COBALT, "application": "Cobalt Strike", "verified": False},
    # Shares cobalt's b+c but different ja4_a -> near.
    {"ja4_fingerprint": "q12d210600_b973bfd88a0e_1da50ec048a3",
     "application": "Cobalt Strike (QUIC)", "verified": False},
]


def make_lookup(records=RECORDS):
    lk = JA4Lookup(cache_dir=None)
    lk._db = list(records)
    lk._build_indexes()
    return lk


def test_smoke_fixture_builds():
    lk = make_lookup()
    assert lk._db is not None


def test_risk_chrome_is_clean():
    risk = parse_ja4(CHROME)["risk"]
    assert risk["level"] == "none"
    assert risk["flags"] == []


def test_risk_sliver_is_high_ip_and_no_alpn():
    risk = parse_ja4(SLIVER)["risk"]
    assert risk["level"] == "high"
    codes = {f["code"] for f in risk["flags"]}
    assert "no_sni_ip" in codes
    assert "no_alpn" in codes


def test_risk_metasploit_is_high():
    assert parse_ja4(METASPLOIT)["risk"]["level"] == "high"


def test_risk_cobalt_medium_only_no_alpn():
    risk = parse_ja4(COBALT)["risk"]
    assert risk["level"] == "medium"
    assert {f["code"] for f in risk["flags"]} == {"no_alpn"}


def test_risk_legacy_tls_is_high():
    risk = parse_ja4("t10d1516h2_8daaf6152771_d8a2da3f94cd")["risk"]
    assert risk["level"] == "high"
    assert any(f["code"] == "legacy_tls" for f in risk["flags"])


def test_assess_risk_direct_call():
    r = assess_risk("t", "13", "i", "00", 19, 8)
    assert r["level"] == "high"


from datetime import timedelta  # noqa: E402


def test_default_cache_window_is_one_hour():
    lk = JA4Lookup(cache_dir=None)
    assert lk.cache_duration == timedelta(hours=1)


def test_indexes_include_ac_and_struct():
    lk = make_lookup()
    assert ("t13d1516h2", "d8a2da3f94cd") in lk._indexes["ac"]
    # struct is a list of (record, components, risk) triples for hunting.
    assert any(comp["sni"]["code"] == "i" for _, comp, _ in lk._indexes["struct"])


from ja4lookr import is_browser_record  # noqa: E402


def test_lookup_exact():
    matches, mt = make_lookup().lookup(CHROME)
    assert mt == "exact"
    assert matches[0]["application"] == "Chrome"


def test_lookup_near_same_b_c_diff_a():
    # Query shares cobalt's b+c but a different ja4_a -> near.
    matches, mt = make_lookup().lookup("t13d210600_b973bfd88a0e_1da50ec048a3")
    assert mt == "near"


def test_lookup_cipher_variant_same_a_c_diff_b():
    # Same ja4_a + ja4_c as Chrome, novel cipher hash -> cipher_variant.
    matches, mt = make_lookup().lookup("t13d1516h2_aaaaaaaaaaaa_d8a2da3f94cd")
    assert mt == "cipher_variant"
    assert any(is_browser_record(r) for r in matches)


def test_lookup_none():
    matches, mt = make_lookup().lookup("t13d9999z9_000000000000_111111111111")
    assert mt == "none"


def test_is_browser_record():
    assert is_browser_record({"application": "Chrome"})
    assert not is_browser_record({"application": "Sliver"})


def test_hunt_no_sni_finds_ip_only():
    hits = make_lookup().hunt({"no-sni"})
    apps = {r["application"] for r in hits}
    assert "Sliver" in apps
    assert "Chrome" not in apps


def test_hunt_no_alpn_finds_c2():
    apps = {r["application"] for r in make_lookup().hunt({"no-alpn"})}
    assert {"Sliver", "Cobalt Strike"} <= apps


def test_hunt_risky_excludes_clean_chrome():
    apps = {r["application"] for r in make_lookup().hunt({"risky"})}
    assert "Chrome" not in apps
    assert "Sliver" in apps


def test_hunt_composes_criteria():
    # no-sni AND no-alpn -> only the IP-only C2 (Sliver), not Cobalt (has SNI).
    apps = {r["application"] for r in make_lookup().hunt({"no-sni", "no-alpn"})}
    assert apps == {"Sliver"}


def test_search_metadata_by_app():
    hits = make_lookup().search_metadata("sliver")
    assert any(r["ja4_fingerprint"] == SLIVER for r in hits)


def test_search_metadata_field_scoped():
    hits = make_lookup().search_metadata("Mozilla", field="user_agent_string")
    assert len(hits) == 1
    assert hits[0]["application"] == "Chrome"


def test_search_metadata_empty_term():
    assert make_lookup().search_metadata("   ") == []
