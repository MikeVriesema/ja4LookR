"""Tests for ja4lookr — no network; a synthetic DB is injected directly."""
import os
import sys

import pytest

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


from ja4lookr import VirusTotalLookup  # noqa: E402


def test_vt_verify_key_no_key(monkeypatch):
    monkeypatch.delenv("VIRUSTOTAL_API_KEY", raising=False)
    monkeypatch.delenv("VT_API_KEY", raising=False)
    vt = VirusTotalLookup(api_key=None)
    result = vt.verify_key()
    assert result["status"] == "no_key"


def test_vt_is_configured_reads_env(monkeypatch):
    monkeypatch.setenv("VIRUSTOTAL_API_KEY", "deadbeef")
    assert VirusTotalLookup().is_configured()


# ----- JA4+ suite: type detection + structural decoding -----
from ja4lookr import (  # noqa: E402
    detect_ja4_type, signature_breakdown, parse_ja4s, parse_ja4h, parse_ja4t, parse_ja4x,
)

JA4S = "t130200_1301_234ea6891581"
JA4H = "ge11cn20enus_9dc949149365_e5627efa2ab1_a1cf8d1e2f3b"
JA4T = "1024_2-4-8-1-3_1460_8"
JA4X = "2bab15409345_af684594efb4_000000000000"


JA4H3 = "ge11cn060000_4e59edc1297a_4da5efaf0cbd"   # 3-section JA4H (no cookie-value hash)
JA4TSCAN = "28960_2-4-8-1-3_1460_3_1-4-8-16"


def test_detect_types():
    assert detect_ja4_type(CHROME) == "ja4"
    assert detect_ja4_type(JA4S) == "ja4s"
    assert detect_ja4_type(JA4H) == "ja4h"
    assert detect_ja4_type(JA4H3) == "ja4h"          # 3-part JA4H
    assert detect_ja4_type(JA4T) == "ja4t"
    assert detect_ja4_type(JA4TSCAN) == "ja4tscan"   # 5-part TCP scan
    assert detect_ja4_type(JA4X) == "ja4x"
    assert detect_ja4_type("t13d190900_*_97f8aa674fd9") == "unknown"  # wildcard
    assert detect_ja4_type("garbage") == "unknown"


def test_breakdown_ja4h_3part_and_scan():
    sig = signature_breakdown(JA4H3)
    assert sig["type"] == "ja4h" and sig["valid"]
    assert len(sig["segments"]) == 3                 # a/b/c, no d
    assert signature_breakdown(JA4TSCAN)["type"] == "ja4tscan"


# Real-world fingerprints from the FoxIO ja4plus mapping — every suite member
# must classify correctly and produce a valid decode.
SUITE_CASES = {
    "ja4":   "t13d1516h2_8daaf6152771_02713d6af862",   # Chrome
    "ja4s":  "t120300_c030_5e2616a54c73",              # IcedID
    "ja4x":  "2166164053c1_2166164053c1_30d204a01551", # Cobalt Strike cert
    "ja4h":  "ge11cn020000_9ed1ff1f7b03_cd8dafe26982", # IcedID dropper (3-part)
    "ja4ssh": "c76s76_c71s59_c0s70",                   # reverse SSH shell
    "ja4l":  "5191_42_45014",                          # latency / light-distance
    "ja4t":  "64240_2-1-3-1-1-4_1460_8",               # Windows 11
    "ja4tscan": "28960_2-4-8-1-3_1460_3_1-4-8-16",     # Epson printer
    "ja4d":  "disco0000in_61-12-60-55_1-3-6-15-31-33-43-44-46-47-119-121-249-252",
    "ja4d6": "solct0010nn_8-1-3-6_24-23",              # Sony receiver
}


@pytest.mark.parametrize("want,fp", list(SUITE_CASES.items()))
def test_full_suite_detection_and_decode(want, fp):
    assert detect_ja4_type(fp) == want
    sig = signature_breakdown(fp)
    assert sig["valid"] and sig["type"] == want
    assert sig["segments"] and sig["decode"]


def test_ja4h_two_part_darkgate_lumma():
    for fp in ("po10nn060000_cdb958d032b0", "po11nn050000_d253db9d024b"):
        sig = signature_breakdown(fp)
        assert sig["type"] == "ja4h" and sig["valid"]
        assert len(sig["segments"]) == 2             # a/b only


def test_breakdown_ja4_has_risk_and_segments():
    sig = signature_breakdown(SLIVER)
    assert sig["type"] == "ja4" and sig["valid"]
    assert sig["risk"]["level"] == "high"
    assert len(sig["segments"]) == 3              # JA4_a / b / c
    assert len(sig["segments"][0]["chars"]) == 6  # 6 ja4_a fields


def test_breakdown_ja4h_fields():
    d = parse_ja4h(JA4H)
    labels = {f["label"]: f["meaning"] for f in d["fields"]}
    assert labels["Method"] == "GET"
    assert labels["HTTP version"] == "HTTP/1.1"
    assert "present" in labels["Cookie"]
    sig = signature_breakdown(JA4H)
    assert sig["type"] == "ja4h" and sig["risk"] is None
    assert len(sig["segments"]) == 4              # JA4H a/b/c/d


def test_breakdown_ja4s_ja4t_ja4x():
    assert "server" in parse_ja4s(JA4S)["summary"]
    assert "window 1024" in parse_ja4t(JA4T)["summary"]
    assert parse_ja4x(JA4X)["fields"][0]["label"] == "Issuer RDNs"
    for fp, t in [(JA4S, "ja4s"), (JA4T, "ja4t"), (JA4X, "ja4x")]:
        assert signature_breakdown(fp)["type"] == t


def test_breakdown_invalid_is_marked():
    assert signature_breakdown("t13d190900_*_97f8aa674fd9")["valid"] is False
    assert signature_breakdown("nonsense")["valid"] is False


def test_vt_type_gate_rejects_non_tls():
    # A configured key must not fire a network call for HTTP/cert/TCP members.
    vt = VirusTotalLookup(api_key="deadbeef")
    assert vt.lookup_ja4(JA4H)["status"] == "unsupported_type"
    assert vt.lookup_ja4(JA4X)["status"] == "unsupported_type"
