# JA4 Threat-Hunting Upgrade — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add automatic risk flags (legacy TLS / IP-only `i` / ALPN `00`), structural hunting filters, a `cipher_variant` browser-mimicry match tier, reverse metadata search, robust env-key VirusTotal handling, and a 1-hour live JA4DB refresh — across both CLI and web, with tests and a clear README.

**Architecture:** All detection logic lives in `ja4lookr.py` as the single source of truth. `app.py` and the Jinja templates consume the same functions. Tests inject a synthetic in-memory DB (no network).

**Tech Stack:** Python 3, `requests`, Flask, pytest.

---

## File Structure

- `ja4lookr.py` — core engine: `assess_risk`, `parse_ja4` (+risk), `JA4Lookup` (1-hour cache, `(a,c)` index, `cipher_variant` tier, `hunt`, `search_metadata`), `VirusTotalLookup.verify_key`, new CLI flags + formatters.
- `tests/test_ja4lookr.py` — new pytest suite, synthetic DB.
- `app.py` — `/hunt`, `/search` routes; risk + VT status in existing routes.
- `templates/index.html` — About risk-engine explainer + Hunt panel + reverse-search box.
- `templates/result.html` — render risk flags + `cipher_variant` note.
- `templates/hunt_result.html`, `templates/search_result.html` — new result pages.
- `requirements.txt` — add `pytest`.
- `README.md` — full rewrite covering CLI + web.
- `.env.example` — note cache behavior.

---

## Task 1: Test scaffolding + synthetic DB

**Files:**
- Create: `tests/test_ja4lookr.py`
- Modify: `requirements.txt`

- [ ] **Step 1: Add pytest to requirements**

In `requirements.txt`, under `# Security` block add a new section at end:
```
# Testing
pytest>=8.0.0
```

- [ ] **Step 2: Create the test file with shared fixtures**

Create `tests/test_ja4lookr.py`:
```python
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
```

- [ ] **Step 3: Run to confirm collection works (assess_risk import will fail until Task 2)**

Run: `python -m pytest tests/test_ja4lookr.py -v`
Expected: ImportError on `assess_risk` (it does not exist yet) — confirms the test imports the not-yet-written function. This is the failing state for Task 2.

- [ ] **Step 4: Commit**

```bash
git add tests/test_ja4lookr.py requirements.txt
git commit -m "test: scaffold ja4lookr test suite with synthetic DB"
```

---

## Task 2: Risk-flag engine (`assess_risk`) + parse integration

**Files:**
- Modify: `ja4lookr.py` (add constants + `assess_risk`, wire into `parse_ja4`)
- Test: `tests/test_ja4lookr.py`

- [ ] **Step 1: Write failing tests**

Append to `tests/test_ja4lookr.py`:
```python
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
```

- [ ] **Step 2: Run to verify failure**

Run: `python -m pytest tests/test_ja4lookr.py -k risk -v`
Expected: FAIL — `assess_risk` undefined / `parse_ja4` has no `risk` key.

- [ ] **Step 3: Implement `assess_risk` and wire into `parse_ja4`**

In `ja4lookr.py`, after the `ALPN_KNOWN = {...}` block (around line 69), add:
```python
LEGACY_TLS = {"11", "10", "s3", "s2", "s1"}
SEVERITY_POINTS = {"info": 0, "low": 1, "medium": 2, "high": 4}


def assess_risk(transport, tls_ver, sni, alpn, cipher_n=None, ext_n=None):
    """Score threat-hunting risk for a parsed JA4_a.

    Mirrors the FoxIO threat-hunting guidance: legacy TLS, IP-only (no SNI),
    and absent ALPN are the indicators to look for. The IP-only + no-ALPN
    combination is the classic C2 shape (Sliver, Metasploit) and escalates
    to ``high``.
    """
    flags = []
    if tls_ver in LEGACY_TLS:
        flags.append({
            "code": "legacy_tls", "severity": "high",
            "title": f"Legacy TLS ({TLS_VERSIONS.get(tls_ver, tls_ver)})",
            "detail": "Pre-TLS-1.2 handshake. Rare for current legitimate clients; "
                      "common in old malware, scanners, and embedded/IoT stacks.",
        })
    if sni == "i":
        flags.append({
            "code": "no_sni_ip", "severity": "medium",
            "title": "Direct-to-IP / no SNI",
            "detail": "Connected to an IP with no server name. Browsers almost always "
                      "send SNI; IP-only TLS is typical of C2 (Sliver, Metasploit) and "
                      "custom tooling.",
        })
    if alpn == "00":
        flags.append({
            "code": "no_alpn", "severity": "medium",
            "title": "No ALPN advertised",
            "detail": "No application protocol negotiated. Alongside a browser-like "
                      "handshake this suggests a minimal/custom TLS stack (malware or "
                      "custom tooling) rather than a real browser.",
        })
    if transport == "q":
        flags.append({
            "code": "quic", "severity": "info",
            "title": "QUIC transport",
            "detail": "TLS 1.3 carried in QUIC. Informational.",
        })

    score = sum(SEVERITY_POINTS[f["severity"]] for f in flags)
    codes = {f["code"] for f in flags}
    combo = {"no_sni_ip", "no_alpn"} <= codes
    if combo:
        score += 3
    has_high = any(f["severity"] == "high" for f in flags)
    has_medium = any(f["severity"] == "medium" for f in flags)
    if has_high or combo or score >= 6:
        level = "high"
    elif has_medium:
        level = "medium"
    elif score >= 1:
        level = "low"
    else:
        level = "none"
    return {"level": level, "score": score, "flags": flags}
```

Then in `parse_ja4`, in the returned dict, add a `risk` key. Change the tail of the returned dict (the `is_tls13`/`is_tls12`/`is_quic` block near line 123) to insert before it:
```python
        "risk": assess_risk(transport, tls_ver, sni, alpn, cipher_n, ext_n),
        "is_tls13": tls_ver == "13",
        "is_tls12": tls_ver == "12",
        "is_quic": transport == "q",
```

- [ ] **Step 4: Run to verify pass**

Run: `python -m pytest tests/test_ja4lookr.py -k risk -v`
Expected: PASS (all 6 risk tests).

- [ ] **Step 5: Commit**

```bash
git add ja4lookr.py tests/test_ja4lookr.py
git commit -m "feat: add JA4 risk-flag engine (legacy TLS, IP-only, no-ALPN)"
```

---

## Task 3: 1-hour live JA4DB refresh

**Files:**
- Modify: `ja4lookr.py` (cache constant + constructor)
- Test: `tests/test_ja4lookr.py`

- [ ] **Step 1: Write failing test**

Append to `tests/test_ja4lookr.py`:
```python
from datetime import timedelta  # noqa: E402


def test_default_cache_window_is_one_hour():
    lk = JA4Lookup(cache_dir=None)
    assert lk.cache_duration == timedelta(hours=1)
```

- [ ] **Step 2: Run to verify failure**

Run: `python -m pytest tests/test_ja4lookr.py -k cache_window -v`
Expected: FAIL — default is currently 1 day.

- [ ] **Step 3: Implement 1-hour window**

In `ja4lookr.py`, replace the constant (around line 34):
```python
DB_CACHE_DAYS = 1
```
with:
```python
DB_CACHE_MAX_AGE = timedelta(hours=1)
```
Update the `JA4Lookup.__init__` signature and body (around line 158):
```python
    def __init__(self, cache_dir=DEFAULT_CACHE_DIR, max_age=DB_CACHE_MAX_AGE):
        self.cache_dir = Path(cache_dir) if cache_dir else None
        if self.cache_dir:
            self.cache_dir.mkdir(parents=True, exist_ok=True)
        self.cache_duration = max_age
        self._db = None
        self._indexes = None
```
`timedelta` is already imported at the top of the file (line 19), so no import change is needed.

- [ ] **Step 4: Run to verify pass**

Run: `python -m pytest tests/test_ja4lookr.py -k cache_window -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add ja4lookr.py tests/test_ja4lookr.py
git commit -m "feat: refresh JA4DB cache hourly (was daily) for fresher data"
```

---

## Task 4: `(a,c)` index + structural cache in `_build_indexes`

**Files:**
- Modify: `ja4lookr.py` (`_build_indexes`)
- Test: `tests/test_ja4lookr.py`

- [ ] **Step 1: Write failing test**

Append to `tests/test_ja4lookr.py`:
```python
def test_indexes_include_ac_and_struct():
    lk = make_lookup()
    assert ("t13d1516h2", "d8a2da3f94cd") in lk._indexes["ac"]
    # struct is a list of (record, components, risk) triples for hunting.
    assert any(comp["sni"]["code"] == "i" for _, comp, _ in lk._indexes["struct"])
```

- [ ] **Step 2: Run to verify failure**

Run: `python -m pytest tests/test_ja4lookr.py -k indexes_include -v`
Expected: FAIL — `ac`/`struct` keys do not exist.

- [ ] **Step 3: Implement**

In `ja4lookr.py`, replace the body of `_build_indexes` (around lines 201-215) with:
```python
    def _build_indexes(self):
        if self._indexes is not None:
            return
        exact, cipher_idx, ext_idx, ac_idx = {}, {}, {}, {}
        struct = []
        for r in self._db:
            for field in self.FP_FIELDS:
                fp = r.get(field)
                if fp:
                    exact.setdefault(fp.lower(), []).append(r)
            ja4 = r.get("ja4_fingerprint")
            if ja4 and ja4.count("_") == 2:
                a, b, c = ja4.split("_")
                cipher_idx.setdefault(b.lower(), []).append(r)
                ext_idx.setdefault(c.lower(), []).append(r)
                ac_idx.setdefault((a.lower(), c.lower()), []).append(r)
                parsed = parse_ja4(ja4)
                if parsed:
                    struct.append((r, parsed["components"], parsed["risk"]))
        self._indexes = {"exact": exact, "cipher": cipher_idx,
                         "extension": ext_idx, "ac": ac_idx, "struct": struct}
```

- [ ] **Step 4: Run to verify pass**

Run: `python -m pytest tests/test_ja4lookr.py -k indexes_include -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add ja4lookr.py tests/test_ja4lookr.py
git commit -m "perf: precompute (a,c) index and structural cache in one pass"
```

---

## Task 5: `cipher_variant` match tier + browser-mimicry helper

**Files:**
- Modify: `ja4lookr.py` (`lookup`, add `is_browser_record`, `BROWSER_HINTS`)
- Test: `tests/test_ja4lookr.py`

- [ ] **Step 1: Write failing tests**

Append to `tests/test_ja4lookr.py`:
```python
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
```

- [ ] **Step 2: Run to verify failure**

Run: `python -m pytest tests/test_ja4lookr.py -k "cipher_variant or is_browser or lookup_near or lookup_exact or lookup_none" -v`
Expected: FAIL — `is_browser_record` undefined and `cipher_variant` tier missing.

- [ ] **Step 3: Implement**

In `ja4lookr.py`, after the `defang` function (around line 144), add:
```python
BROWSER_HINTS = ("chrome", "chromium", "firefox", "safari", "edge",
                 "brave", "opera")


def is_browser_record(r):
    """True if a JA4DB record looks like a mainstream web browser."""
    blob = " ".join(str(r.get(k) or "") for k in
                    ("application", "library", "user_agent_string")).lower()
    return any(h in blob for h in BROWSER_HINTS)
```

In `lookup`, insert the `cipher_variant` tier between the `near` check and the
`partial` check. Replace the block (current lines ~246-255):
```python
        _, b, c = fp.split("_")
        cipher_hits = self._indexes["cipher"].get(b, [])
        ext_hits = self._indexes["extension"].get(c, [])
        near = [r for r in cipher_hits
                if (r.get("ja4_fingerprint") or "").lower().endswith(f"_{b}_{c}")]
        if near:
            return near, "near"
        if cipher_hits or ext_hits:
            return {"cipher_matches": cipher_hits, "extension_matches": ext_hits}, "partial"
        return [], "none"
```
with:
```python
        a, b, c = fp.split("_")
        cipher_hits = self._indexes["cipher"].get(b, [])
        ext_hits = self._indexes["extension"].get(c, [])
        near = [r for r in cipher_hits
                if (r.get("ja4_fingerprint") or "").lower().endswith(f"_{b}_{c}")]
        if near:
            return near, "near"
        ac_hits = self._indexes["ac"].get((a, c), [])
        variant = [r for r in ac_hits
                   if (r.get("ja4_fingerprint") or "").lower() != fp]
        if variant:
            return variant, "cipher_variant"
        if cipher_hits or ext_hits:
            return {"cipher_matches": cipher_hits, "extension_matches": ext_hits}, "partial"
        return [], "none"
```
Note: the only functional change to the first line is binding `a` instead of `_`.

- [ ] **Step 4: Run to verify pass**

Run: `python -m pytest tests/test_ja4lookr.py -k "cipher_variant or is_browser or lookup_near or lookup_exact or lookup_none" -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add ja4lookr.py tests/test_ja4lookr.py
git commit -m "feat: add cipher_variant match tier (stable a+c, varying b) + browser-mimicry helper"
```

---

## Task 6: Database hunting (`hunt`)

**Files:**
- Modify: `ja4lookr.py` (add `JA4Lookup.hunt`)
- Test: `tests/test_ja4lookr.py`

- [ ] **Step 1: Write failing tests**

Append to `tests/test_ja4lookr.py`:
```python
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
```

- [ ] **Step 2: Run to verify failure**

Run: `python -m pytest tests/test_ja4lookr.py -k hunt -v`
Expected: FAIL — `hunt` undefined.

- [ ] **Step 3: Implement**

In `ja4lookr.py`, add this method to `JA4Lookup` (place after `lookup`, before `batch_lookup`):
```python
    HUNT_CRITERIA = ("legacy-tls", "no-sni", "no-alpn", "risky", "quic")

    def hunt(self, criteria, app_filter=None, verified_only=False, limit=None):
        """Return DB records whose JA4 matches structural hunting criteria.

        criteria: iterable of tokens from HUNT_CRITERIA. Multiple tokens are
        ANDed together. ``risky`` = computed risk level medium or high.
        """
        self._load()
        self._build_indexes()
        crit = {c.strip().lower() for c in criteria if c and c.strip()}
        out = []
        for r, comp, risk in self._indexes["struct"]:
            transport = comp["transport"]["code"]
            tls = comp["tls_version"]["code"]
            sni = comp["sni"]["code"]
            alpn = comp["alpn"]["code"]
            if "legacy-tls" in crit and tls not in LEGACY_TLS:
                continue
            if "no-sni" in crit and sni != "i":
                continue
            if "no-alpn" in crit and alpn != "00":
                continue
            if "quic" in crit and transport != "q":
                continue
            if "risky" in crit and risk["level"] not in ("medium", "high"):
                continue
            if app_filter and (r.get("application") or "").lower() != app_filter.lower():
                continue
            if verified_only and not r.get("verified"):
                continue
            out.append(r)
        return out[:limit] if limit else out
```

- [ ] **Step 4: Run to verify pass**

Run: `python -m pytest tests/test_ja4lookr.py -k hunt -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add ja4lookr.py tests/test_ja4lookr.py
git commit -m "feat: add structural DB hunting (legacy-tls/no-sni/no-alpn/risky/quic)"
```

---

## Task 7: Reverse metadata search (`search_metadata`)

**Files:**
- Modify: `ja4lookr.py` (add `JA4Lookup.search_metadata` + `META_FIELDS`)
- Test: `tests/test_ja4lookr.py`

- [ ] **Step 1: Write failing tests**

Append to `tests/test_ja4lookr.py`:
```python
def test_search_metadata_by_app():
    hits = make_lookup().search_metadata("sliver")
    assert any(r["ja4_fingerprint"] == SLIVER for r in hits)


def test_search_metadata_field_scoped():
    hits = make_lookup().search_metadata("Mozilla", field="user_agent_string")
    assert len(hits) == 1
    assert hits[0]["application"] == "Chrome"


def test_search_metadata_empty_term():
    assert make_lookup().search_metadata("   ") == []
```

- [ ] **Step 2: Run to verify failure**

Run: `python -m pytest tests/test_ja4lookr.py -k search_metadata -v`
Expected: FAIL — `search_metadata` undefined.

- [ ] **Step 3: Implement**

In `ja4lookr.py`, add to `JA4Lookup` (after `hunt`):
```python
    META_FIELDS = ("application", "library", "device", "os",
                   "user_agent_string", "notes")

    def search_metadata(self, term, field=None, limit=None):
        """Reverse lookup: find records by metadata substring (case-insensitive).

        Searches all META_FIELDS, or one ``field`` if given. Returns the full
        records (including their fingerprints) — the inverse of a JA4 lookup.
        """
        self._load()
        self._build_indexes()
        term_l = (term or "").lower().strip()
        if not term_l:
            return []
        fields = (field,) if field else self.META_FIELDS
        out = []
        for r in self._db:
            for f in fields:
                v = r.get(f)
                if v and term_l in str(v).lower():
                    out.append(r)
                    break
        return out[:limit] if limit else out
```

- [ ] **Step 4: Run to verify pass**

Run: `python -m pytest tests/test_ja4lookr.py -k search_metadata -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add ja4lookr.py tests/test_ja4lookr.py
git commit -m "feat: add reverse metadata search (ja4db-search parity+)"
```

---

## Task 8: VirusTotal key verification

**Files:**
- Modify: `ja4lookr.py` (add `VirusTotalLookup.verify_key`)
- Test: `tests/test_ja4lookr.py`

- [ ] **Step 1: Write failing test (no-network path only)**

Append to `tests/test_ja4lookr.py`:
```python
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
```

- [ ] **Step 2: Run to verify failure**

Run: `python -m pytest tests/test_ja4lookr.py -k vt_ -v`
Expected: FAIL — `verify_key` undefined.

- [ ] **Step 3: Implement**

In `ja4lookr.py`, add to `VirusTotalLookup` (after `is_configured`):
```python
    def verify_key(self):
        """Check the configured key: no_key / invalid / valid / valid_no_intelligence."""
        if not self.api_key:
            return {"status": "no_key",
                    "message": "No VT API key set (VIRUSTOTAL_API_KEY or VT_API_KEY)"}
        try:
            self._get("/metadata", timeout=15)
        except PermissionError as e:
            if "Invalid" in str(e):
                return {"status": "invalid", "message": str(e)}
        except requests.exceptions.RequestException as e:
            return {"status": "error", "message": str(e)}
        try:
            self._get("/intelligence/search",
                      params={"query": "entity:file", "limit": 1}, timeout=15)
            return {"status": "valid",
                    "message": "Key valid; VT Intelligence (behavior_network) available"}
        except PermissionError:
            return {"status": "valid_no_intelligence",
                    "message": "Key valid but lacks VT Intelligence; behavior_network: "
                               "searches need a Premium/Enterprise key"}
        except requests.exceptions.RequestException as e:
            return {"status": "error", "message": str(e)}
```

- [ ] **Step 4: Run to verify pass**

Run: `python -m pytest tests/test_ja4lookr.py -k vt_ -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add ja4lookr.py tests/test_ja4lookr.py
git commit -m "feat: add VT key verification (distinguishes invalid vs no-Intelligence)"
```

---

## Task 9: CLI wiring + formatters

**Files:**
- Modify: `ja4lookr.py` (formatters + `main`)

- [ ] **Step 1: Add risk + cipher_variant + hunt/search formatters**

In `ja4lookr.py`, after `format_lookup` (around line 512) add:
```python
RISK_GLYPH = {"high": "[!!]", "medium": "[!]", "low": "[.]",
              "none": "[ok]", "info": "[i]"}


def format_risk(risk):
    if not risk or not risk.get("flags"):
        return "   Risk: none (no legacy TLS, SNI present, ALPN advertised)"
    lines = [f"   Risk: {risk['level'].upper()} (score {risk['score']})"]
    for f in risk["flags"]:
        lines.append(f"     {RISK_GLYPH.get(f['severity'], '[?]')} "
                     f"{f['title']} — {f['detail']}")
    return "\n".join(lines)


def format_records(records, cap=25):
    lines = []
    for r in records[:cap]:
        lines.append("---")
        if r.get("ja4_fingerprint"):
            lines.append(f"   ja4           {r.get('ja4_fingerprint')}")
        lines.extend(_record_lines(r))
    if len(records) > cap:
        lines.append(f"   ... {len(records) - cap} more (full list in JSON output)")
    return "\n".join(lines)


def format_hunt(criteria, records):
    head = (f"\nHunt: {', '.join(sorted(criteria))} — "
            f"{len(records)} matching JA4DB record(s)")
    return head + ("\n" + format_records(records) if records else
                   "\n   No DB records match these criteria.")


def format_search(term, field, records):
    scope = f"field={field}" if field else "all metadata fields"
    head = f"\nReverse search: '{term}' ({scope}) — {len(records)} record(s)"
    return head + ("\n" + format_records(records) if records else
                   "\n   No DB records match.")
```

Add the `cipher_variant` branch inside `format_lookup`, immediately after the
`elif mt == "near":` block (after its loop, before `elif mt == "wildcard":`):
```python
    elif mt == "cipher_variant":
        records = _filter(matches)
        mimic = any(is_browser_record(r) for r in records)
        note = (" — a+c match a known BROWSER; possible mimicry/impersonation"
                if mimic else "")
        lines.append(f"[~] Cipher variant: same ja4_a + ja4_c, different cipher "
                     f"hash ({len(records)} record(s)){note}")
        lines.append("   Pivot: actor may be randomizing cipher order; hunt on "
                     "*_<ext_hash> with this ja4_a.")
        for r in records[:25]:
            lines.append("---")
            lines.append(f"   ja4           {r.get('ja4_fingerprint')}")
            lines.extend(_record_lines(r))
```

- [ ] **Step 2: Add CLI arguments**

In `main`, after the `--yara` argument (around line 586) add:
```python
    p.add_argument("--hunt",
                   help="Hunt the JA4DB by structural criteria (no fingerprint "
                        "needed). Comma-separated: legacy-tls,no-sni,no-alpn,risky,quic")
    p.add_argument("--search",
                   help="Reverse lookup: find fingerprints by metadata substring "
                        "(application/UA/library/device/os/notes)")
    p.add_argument("--field",
                   help="Restrict --search to one metadata field "
                        "(e.g. application, user_agent_string)")
    p.add_argument("--vt-check", action="store_true",
                   help="Verify the VirusTotal API key/privileges and exit")
```

- [ ] **Step 3: Wire the new modes into `main`**

In `main`, immediately after `args = p.parse_args()` and the `cache_dir`/`lookup`
setup (after line 598, before `vt = VirusTotalLookup() if args.vt else None`),
insert the early-exit modes:
```python
    if args.vt_check:
        status = VirusTotalLookup().verify_key()
        print(f"VirusTotal key: {status['status']} — {status['message']}")
        return

    if args.hunt:
        criteria = [c for c in args.hunt.split(",") if c.strip()]
        records = lookup.hunt(criteria, app_filter=args.application,
                              verified_only=args.verified_only)
        print(format_hunt(set(criteria), records))
        out = {"timestamp": datetime.now().isoformat(), "mode": "hunt",
               "criteria": criteria, "count": len(records), "records": records}
        if args.as_json:
            print(json.dumps(out, indent=2, default=str))
        if args.output != "-":
            out_path = Path(args.output) if args.output else Path(default_output_path())
            with open(out_path, "w", encoding="utf-8") as f:
                json.dump(out, f, indent=2, default=str)
            print(f"\n[+] JSON results written to {out_path}", file=sys.stderr)
        return

    if args.search:
        records = lookup.search_metadata(args.search, field=args.field)
        print(format_search(args.search, args.field, records))
        out = {"timestamp": datetime.now().isoformat(), "mode": "search",
               "term": args.search, "field": args.field,
               "count": len(records), "records": records}
        if args.as_json:
            print(json.dumps(out, indent=2, default=str))
        if args.output != "-":
            out_path = Path(args.output) if args.output else Path(default_output_path())
            with open(out_path, "w", encoding="utf-8") as f:
                json.dump(out, f, indent=2, default=str)
            print(f"\n[+] JSON results written to {out_path}", file=sys.stderr)
        return
```

In `run_one`, after the `print(format_lookup(...))` call (around line 615), add a
risk line so every lookup shows its risk:
```python
        if record.get("parsed") and record["parsed"].get("risk"):
            print(format_risk(record["parsed"]["risk"]))
```

- [ ] **Step 4: Smoke-test the CLI (offline, using the live cache if present)**

Run: `python ja4lookr.py --help`
Expected: help text lists `--hunt`, `--search`, `--field`, `--vt-check`.

Run: `python -c "import ja4lookr"`
Expected: no error (module imports cleanly).

- [ ] **Step 5: Commit**

```bash
git add ja4lookr.py
git commit -m "feat: CLI support for risk display, hunt, reverse search, and --vt-check"
```

---

## Task 10: Web routes — risk, hunt, search, VT status

**Files:**
- Modify: `app.py`

- [ ] **Step 1: Update imports and `format_result`**

In `app.py`, extend the import (line 12) to:
```python
from ja4lookr import (JA4Lookup, VirusTotalLookup, parse_ja4, yara_rule_for,
                      has_wildcard, is_browser_record)
```
Add a label and make `cipher_variant` render as a found list. In
`MATCH_TYPE_LABEL` add:
```python
    'cipher_variant': 'Cipher variant (same a+c, different cipher hash — possible randomization/mimicry)',
```
In `format_result`, change the found-tier check to include `cipher_variant` and
attach a mimicry flag. Replace:
```python
    if match_type in ('exact', 'near', 'wildcard'):
        return {**base, 'found': True, 'entries': matches, 'count': len(matches)}
```
with:
```python
    if match_type in ('exact', 'near', 'wildcard', 'cipher_variant'):
        result = {**base, 'found': True, 'entries': matches, 'count': len(matches)}
        if match_type == 'cipher_variant':
            result['browser_mimicry'] = any(is_browser_record(r) for r in matches)
        return result
```

- [ ] **Step 2: Add `/hunt` and `/search` routes**

In `app.py`, after the `batch_lookup` route (after line 184) add:
```python
HUNT_CRITERIA = ("legacy-tls", "no-sni", "no-alpn", "risky", "quic")


@app.route('/hunt', methods=['POST'])
@limiter.limit("20 per minute")
def hunt():
    """Hunt the JA4DB by structural criteria."""
    criteria = [c for c in request.form.getlist('criteria') if c in HUNT_CRITERIA]
    if not criteria:
        flash('Select at least one hunting criterion', 'error')
        return redirect(url_for('index'))
    try:
        records = ja4_lookup.hunt(criteria, limit=500)
        return render_template('hunt_result.html',
                               criteria=criteria, records=records,
                               count=len(records),
                               timestamp=datetime.now().strftime('%Y-%m-%d %H:%M:%S'))
    except Exception as e:
        flash(f'Hunt error: {str(e)}', 'error')
        return redirect(url_for('index'))


@app.route('/search', methods=['POST'])
@limiter.limit("30 per minute")
def search():
    """Reverse lookup by application / User-Agent / metadata."""
    term = request.form.get('term', '').strip()
    field = request.form.get('field', '').strip() or None
    if not term:
        flash('Enter a search term', 'error')
        return redirect(url_for('index'))
    try:
        records = ja4_lookup.search_metadata(term, field=field, limit=500)
        return render_template('search_result.html',
                               term=term, field=field, records=records,
                               count=len(records),
                               timestamp=datetime.now().strftime('%Y-%m-%d %H:%M:%S'))
    except Exception as e:
        flash(f'Search error: {str(e)}', 'error')
        return redirect(url_for('index'))
```

- [ ] **Step 3: Pass VT status to the index page**

In `app.py`, replace the `index` route (lines 80-83) with:
```python
@app.route('/')
def index():
    """Home page with lookup form."""
    return render_template('index.html',
                           vt_configured=vt_lookup.is_configured())
```

- [ ] **Step 4: Smoke-test the import**

Run: `python -c "import app"`
Expected: no error.

- [ ] **Step 5: Commit**

```bash
git add app.py
git commit -m "feat: web routes for hunt, reverse search, cipher_variant, VT status"
```

---

## Task 11: Web templates — About explainer, hunt/search forms, risk rendering

**Files:**
- Modify: `templates/index.html`, `templates/result.html`
- Create: `templates/hunt_result.html`, `templates/search_result.html`

- [ ] **Step 1: Add the risk-engine About explainer + Hunt/Search panels to `index.html`**

In `templates/index.html`, replace the `info-box` block (lines 102-114) with:
```html
<div class="info-box">
    <h3>About JA4 Fingerprints</h3>
    <p>JA4 identifies TLS clients by their handshake characteristics — useful for application
       identification, anomaly detection, and threat hunting. JA4LookR resolves fingerprints
       against a locally cached JA4DB (refreshed hourly) with exact, near, <strong>cipher-variant</strong>,
       wildcard, and partial matching, and optionally pivots to VirusTotal Intelligence.</p>
    <ul>
        <li><strong>JA4</strong>: TLS client fingerprinting · <strong>JA4H</strong>: HTTP · <strong>JA4S</strong>: TLS server</li>
        <li><strong>Wildcards</strong>: use <code>*</code> for any section, e.g. <code>t13d190900_*_97f8aa674fd9</code></li>
    </ul>
    <h3 style="margin-top:18px;">How the risk engine works</h3>
    <p>Every parsed fingerprint is scored for the indicators threat hunters look for. Flags stack into
       an overall level (<strong>none → low → medium → high</strong>):</p>
    <ul>
        <li><strong>Legacy TLS</strong> (<code>11</code>/<code>10</code>/<code>s3</code>…) — pre-TLS-1.2 is rare for legitimate clients today → <em>high</em>.</li>
        <li><strong>Direct-to-IP / no SNI</strong> (the <code>i</code> char, e.g. <code>t13<strong>i</strong>…</code>) — browsers almost always send SNI; IP-only TLS is typical of C2 → <em>medium</em>.</li>
        <li><strong>No ALPN</strong> (<code>00</code>) — no negotiated protocol; with a browser-like handshake this hints at a minimal/custom stack → <em>medium</em>.</li>
        <li><strong>Combo escalation</strong> — IP-only <em>and</em> no-ALPN together is the classic C2 shape and escalates to <em>high</em>.</li>
    </ul>
    <p>Worked examples: <code>t13d1516h2_…</code> (Chrome 137) scores <strong>none</strong>;
       <code>t12d210600_…</code> (Cobalt Strike, no ALPN) <strong>medium</strong>;
       <code>t13i190800_…</code> (Sliver, IP-only + no ALPN) and
       <code>t12i190700_…</code> (Metasploit) score <strong>high</strong>.</p>
</div>
```

- [ ] **Step 2: Add Hunt + Reverse-search tabs to `index.html`**

In `templates/index.html`, replace the tabs nav (lines 116-119) with:
```html
<div class="tabs">
    <button class="tab active" onclick="switchTab('single')">Single Lookup</button>
    <button class="tab" onclick="switchTab('batch')">Batch Lookup</button>
    <button class="tab" onclick="switchTab('hunt')">Hunt DB</button>
    <button class="tab" onclick="switchTab('search')">Reverse Search</button>
</div>
```
Then, immediately after the closing `</div>` of the `#batch` tab-content block
(after line 168), insert:
```html
<div id="hunt" class="tab-content">
    <form method="POST" action="/hunt">
        <div class="form-group">
            <label>Hunt the JA4DB for risky structural patterns:</label>
            <div style="display:flex; flex-direction:column; gap:8px; margin-top:10px;">
                <label style="font-weight:normal;"><input type="checkbox" name="criteria" value="legacy-tls"> Legacy TLS (1.1 / 1.0 / SSL)</label>
                <label style="font-weight:normal;"><input type="checkbox" name="criteria" value="no-sni"> Direct-to-IP / no SNI (<code>i</code>)</label>
                <label style="font-weight:normal;"><input type="checkbox" name="criteria" value="no-alpn"> No ALPN (<code>00</code>)</label>
                <label style="font-weight:normal;"><input type="checkbox" name="criteria" value="quic"> QUIC transport</label>
                <label style="font-weight:normal;"><input type="checkbox" name="criteria" value="risky"> Risky (medium/high overall)</label>
            </div>
            <small style="color:#6b7280; display:block; margin-top:8px;">Multiple selections are ANDed together.</small>
        </div>
        <button type="submit" class="btn">Hunt Database</button>
    </form>
</div>

<div id="search" class="tab-content">
    <form method="POST" action="/search">
        <div class="form-group">
            <label for="term">Find fingerprints by application / User-Agent / metadata:</label>
            <input type="text" id="term" name="term" placeholder="cobalt, curl, Chrome, nmap…" autocomplete="off">
            <div style="margin-top:10px;">
                <label for="field" style="font-weight:normal;">Restrict to field (optional):</label>
                <select id="field" name="field">
                    <option value="">All metadata fields</option>
                    <option value="application">application</option>
                    <option value="library">library</option>
                    <option value="device">device</option>
                    <option value="os">os</option>
                    <option value="user_agent_string">user_agent_string</option>
                    <option value="notes">notes</option>
                </select>
            </div>
        </div>
        <button type="submit" class="btn">Reverse Search</button>
    </form>
</div>
```

- [ ] **Step 3: Render risk flags + cipher_variant note in `result.html`**

In `templates/result.html`, after the parsed-components block closes
(`{% endif %}` following line 167's region — locate the `{% if parsed %}` block
that ends before the JA4DB results) insert a risk panel. Add this immediately
after the line `<div class="detail-value"><code>{{ parsed.ja4_c_extension_hash }}</code></div>`
and its closing tags, inside the `{% if parsed %}` block, before its `{% endif %}`:
```html
            {% if parsed.risk %}
            <div class="risk-panel risk-{{ parsed.risk.level }}" style="margin-top:18px; padding:14px 16px; border-radius:6px; border-left:5px solid;">
                <strong>Risk: {{ parsed.risk.level|upper }}</strong>
                <span style="color:#6b7280;">(score {{ parsed.risk.score }})</span>
                {% if parsed.risk.flags %}
                <ul style="margin:8px 0 0 18px;">
                    {% for f in parsed.risk.flags %}
                    <li><strong>{{ f.title }}</strong> — {{ f.detail }}</li>
                    {% endfor %}
                </ul>
                {% else %}
                <p style="margin-top:6px;">No legacy TLS, SNI present, ALPN advertised.</p>
                {% endif %}
            </div>
            {% endif %}
```
Add matching CSS in the `{% block extra_css %}` of `result.html` (or inline as
above is sufficient). Add this to the `<style>` if a block exists, otherwise the
inline border-left color is set here:
```html
<style>
    .risk-none { background:#f0fdf4; border-left-color:#22c55e; }
    .risk-low { background:#fefce8; border-left-color:#eab308; }
    .risk-medium { background:#fff7ed; border-left-color:#f97316; }
    .risk-high { background:#fef2f2; border-left-color:#ef4444; }
</style>
```
Place that `<style>` block right after `{% block content %}` at the top of
`result.html` content so the classes resolve.

Also surface the browser-mimicry note: find where `result.match_label` is shown
and add below it:
```html
            {% if result.browser_mimicry %}
            <p style="color:#b91c1c; font-weight:600;">⚠ a+c match a known browser — possible mimicry / impersonation.</p>
            {% endif %}
```

- [ ] **Step 4: Create `templates/hunt_result.html`**

Create `templates/hunt_result.html`:
```html
{% extends "base.html" %}
{% block title %}JA4LookR - Hunt Results{% endblock %}
{% block content %}
<h2>Hunt Results</h2>
<p style="color:#6b7280;">Criteria: <strong>{{ criteria|join(', ') }}</strong> ·
   {{ count }} record(s) · {{ timestamp }}</p>
<p><a href="/">&larr; New search</a></p>
{% if records %}
<table style="width:100%; border-collapse:collapse; margin-top:16px;">
    <thead>
        <tr style="text-align:left; border-bottom:2px solid #e5e7eb;">
            <th style="padding:8px;">JA4</th><th style="padding:8px;">Application</th>
            <th style="padding:8px;">Device / OS</th><th style="padding:8px;">Verified</th>
        </tr>
    </thead>
    <tbody>
        {% for r in records %}
        <tr style="border-bottom:1px solid #f0f0f0;">
            <td style="padding:8px; font-family:monospace;">{{ r.ja4_fingerprint }}</td>
            <td style="padding:8px;">{{ r.application or r.library or '—' }}</td>
            <td style="padding:8px;">{{ r.device or '' }} {{ r.os or '' }}</td>
            <td style="padding:8px;">{{ '✓' if r.verified else '' }}</td>
        </tr>
        {% endfor %}
    </tbody>
</table>
{% else %}
<p>No DB records match these criteria.</p>
{% endif %}
{% endblock %}
```

- [ ] **Step 5: Create `templates/search_result.html`**

Create `templates/search_result.html`:
```html
{% extends "base.html" %}
{% block title %}JA4LookR - Reverse Search{% endblock %}
{% block content %}
<h2>Reverse Search Results</h2>
<p style="color:#6b7280;">Term: <strong>{{ term }}</strong>
   {% if field %}(field: {{ field }}){% else %}(all metadata fields){% endif %} ·
   {{ count }} record(s) · {{ timestamp }}</p>
<p><a href="/">&larr; New search</a></p>
{% if records %}
<table style="width:100%; border-collapse:collapse; margin-top:16px;">
    <thead>
        <tr style="text-align:left; border-bottom:2px solid #e5e7eb;">
            <th style="padding:8px;">JA4</th><th style="padding:8px;">Application</th>
            <th style="padding:8px;">User-Agent</th>
        </tr>
    </thead>
    <tbody>
        {% for r in records %}
        <tr style="border-bottom:1px solid #f0f0f0;">
            <td style="padding:8px; font-family:monospace;">{{ r.ja4_fingerprint }}</td>
            <td style="padding:8px;">{{ r.application or r.library or '—' }}</td>
            <td style="padding:8px; font-size:12px;">{{ (r.user_agent_string or '')[:80] }}</td>
        </tr>
        {% endfor %}
    </tbody>
</table>
{% else %}
<p>No DB records match.</p>
{% endif %}
{% endblock %}
```

- [ ] **Step 6: Verify templates load**

Run: `python -c "import app; c=app.app.test_client(); print(c.get('/').status_code)"`
Expected: prints `200` (index renders with new tabs and About explainer).

- [ ] **Step 7: Commit**

```bash
git add templates/index.html templates/result.html templates/hunt_result.html templates/search_result.html
git commit -m "feat: web UI for risk explainer, DB hunting, reverse search, risk rendering"
```

---

## Task 12: README rewrite + `.env.example`

**Files:**
- Modify: `README.md`, `.env.example`

- [ ] **Step 1: Rewrite the README**

Replace `README.md` so it documents, for **both CLI and web**:
- Feature list including risk engine, hunting filters, `cipher_variant` tier, reverse search, hourly refresh.
- A **Risk engine** section: the three indicators (legacy TLS, IP-only `i`, ALPN `00`), the scoring/combo rule, and the worked Chrome/Cobalt/Sliver/Metasploit examples.
- A **Threat-hunting field guide** section (hunt.io-inspired): partial-segment pivoting, cipher randomization (stable a+c / varying b), browser mimicry, ALPN-00 non-browser heuristic — each with a concrete CLI command and the web equivalent.
- A **Hunting the database** section: `python ja4lookr.py --hunt legacy-tls,no-sni,no-alpn` and the web Hunt tab.
- A **Reverse search** section: `python ja4lookr.py --search cobalt --field application` and the web Reverse Search tab.
- A **VirusTotal setup** section: env var names (`VIRUSTOTAL_API_KEY` / `VT_API_KEY`), `.env` usage, `python ja4lookr.py --vt-check`, and the free-vs-Intelligence-key caveat.
- A **Data freshness** note: cache auto-refreshes if older than 1 hour; `--refresh` forces it.
- A **Comparison to sans-blue-team/ja4db-search** table (exact-only vs ja4LookR's tiered matching + risk + hunting + reverse search + VT + web).
- A short **Efficiency notes** section: single-pass index build (exact/cipher/extension/(a,c)/struct), in-RAM lookups, one-time parse cost; wildcard search is a full scan by design.
- A **Testing** section: `python -m pytest -v`.

Keep the existing JA4 format tables (they are accurate). Use the four reference
signatures from the slides as canonical examples throughout.

- [ ] **Step 2: Update `.env.example`**

In `.env.example`, replace the cache-settings comment block at the bottom with:
```
# Cache settings (OPTIONAL)
# The JA4DB is auto-refreshed when the local cache is older than 1 hour.
# CACHE_DIR=.ja4_cache
```

- [ ] **Step 3: Verify README has no stale "daily refresh" claims**

Run: `grep -ni "daily\|per day\|once" README.md`
Expected: no line claims the DB refreshes daily (hourly is the new behavior). Fix any that remain.

- [ ] **Step 4: Commit**

```bash
git add README.md .env.example
git commit -m "docs: rewrite README for risk engine, hunting, reverse search, hourly refresh"
```

---

## Task 13: Full verification

**Files:** none (verification only)

- [ ] **Step 1: Run the whole test suite**

Run: `python -m pytest tests/ -v`
Expected: all tests PASS.

- [ ] **Step 2: CLI smoke (parsing path, no network needed if cache exists)**

Run: `python ja4lookr.py t13i190800_9dc949149365_97f8aa674fd9 --parse -o -`
Expected: output includes the parsed structure and a Risk line at HIGH (IP-only + no ALPN). (If the JA4DB cache is cold this will fetch once; that is expected.)

- [ ] **Step 3: Web smoke**

Run: `python -c "import app; c=app.app.test_client(); print(c.get('/').status_code, c.get('/health').status_code)"`
Expected: `200 200`.

- [ ] **Step 4: Confirm clean git state**

Run: `git status`
Expected: clean working tree; all work committed.

---

## Self-Review Notes

- **Spec coverage:** risk engine (T2), hunting filters (T6), `cipher_variant`/mimicry (T5), reverse search (T7), VT env-key robustness (T8), 1-hour refresh (T3), efficiency single-pass index (T4), CLI parity (T9), web parity + About explainer (T10/T11), README + comparison table (T12), tests throughout. All spec sections map to a task.
- **Types/signatures consistent:** `assess_risk(...)→{level,score,flags}`, `lookup→(matches,match_type)` with new `cipher_variant`, `hunt(criteria,...)→[records]`, `search_metadata(term,field,limit)→[records]`, `verify_key()→{status,message}`, `is_browser_record(r)→bool` — names used identically across CLI, web, and tests.
