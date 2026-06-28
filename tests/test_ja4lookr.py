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
