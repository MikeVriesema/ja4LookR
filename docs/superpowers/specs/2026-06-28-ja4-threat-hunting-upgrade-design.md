# JA4LookR Threat-Hunting Upgrade — Design

Date: 2026-06-28

## Goal

Turn ja4LookR from a JA4DB lookup utility into a threat-hunting tool. Add
automatic risk flags around the indicators called out in the source material
(legacy TLS, the `i` / IP-only-no-SNI character, ALPN `00`), structural hunting
filters over the whole database, a new "cipher variant / browser mimicry" match
tier inspired by hunt.io, reverse metadata search for ja4db-search parity,
robust VirusTotal usage with an env API key, an efficiency pass, tests, and an
updated README.

## Research summary

- **hunt.io JA4 glossary** — key ideas folded in: ALPN `00` as a non-browser /
  minimal-stack heuristic; partial-segment pivoting (JA4_a / JA4_b / JA4_c
  independently); the observation that **JA4_a + JA4_c stay stable while JA4_b
  changes** when an actor randomizes cipher suites, and the inverse "browser
  mimicry" case (a+c match a known browser but the full fingerprint is unknown);
  legacy-TLS hunting; JA4X + certificate-anomaly pairing.
- **sans-blue-team/ja4db-search** — minimal: exact match on `ja4_fingerprint`
  only, prints `ja4_fingerprint` / `application` / `user_agent_string`.
  ja4LookR already exceeds it; the one real gap is **reverse lookup** (find
  fingerprints by application / User-Agent / metadata).

## Reference signatures (from the source slides, used in tests)

| Tool          | JA4                                   | Notes                         |
|---------------|---------------------------------------|-------------------------------|
| Chrome 137    | `t13d1516h2_8daaf6152771_d8a2da3f94cd` | TLS 1.3, SNI, ALPN h2 — clean |
| Cobalt Strike | `t12d210600_b973bfd88a0e_1da50ec048a3` | TLS 1.2, SNI, ALPN 00         |
| Sliver        | `t13i190800_9dc949149365_97f8aa674fd9` | TLS 1.3, IP-only, ALPN 00     |
| Metasploit    | `t12i190700_d83cc789557e_16bbda4055b2` | TLS 1.2, IP-only, ALPN 00     |

## Components

### 1. Risk-flag engine (`ja4lookr.py`)

`assess_risk(transport, tls_ver, sni, alpn, cipher_n, ext_n) -> dict`

Returns:
```
{
  "level": "none" | "low" | "medium" | "high",
  "score": int,
  "flags": [ {"code", "severity", "title", "detail"}, ... ]
}
```

Individual flags:
- `legacy_tls` — `tls_ver` in {`11`,`10`,`s3`,`s2`,`s1`}. SSL = high, TLS 1.0/1.1
  = high. (TLS 1.2 is **not** flagged on its own, only noted in combos.)
- `no_sni_ip` — `sni == "i"` → "Direct-to-IP / no SNI" (medium).
- `no_alpn` — `alpn == "00"` → "No ALPN advertised" (medium); detail carries the
  hunt.io note that `00` alongside a browser-like handshake suggests a
  minimal/custom TLS stack (malware / custom tooling).
- `quic` — `transport == "q"` (informational, severity `info`).

Scoring: each flag contributes points by severity (info 0, low 1, medium 2,
high 4). **Combo escalation:** if `no_sni_ip` AND `no_alpn` are both present
(optionally with TLS 1.2), add a bonus so the overall `level` reaches `high`.
This makes the three C2 examples score high while Chrome 137 stays `none`.

`parse_ja4` gains a `"risk"` key holding this block. CLI `format_lookup` prints
the flags; `result.html` renders them.

### 2. Hunting filters (`JA4Lookup.hunt(criteria, app_filter, verified_only)`)

`criteria` is a set drawn from: `legacy-tls`, `no-sni`, `no-alpn`, `risky`,
`quic`. Iterates the DB using the **pre-parsed structural fields** added to the
index (see §6), applies the predicate, returns matching records. `risky` = any
record whose `assess_risk` level is medium or high.

CLI: `--hunt legacy-tls,no-sni` (comma-composable; when set, no positional
fingerprint required — scans the DB). Composes with `-a/--application` and
`--verified-only`. Output reuses the wildcard/list formatter with a count cap
and "full list in JSON" note.

Web: a "Hunt the database" panel (checkboxes) posting to a new `/hunt` route.

### 3. New match tier — `cipher_variant`

Add an `(ja4_a, ja4_c)` index built in the same pass as the others. Matching
ladder in `lookup()`:

```
exact → near (b+c match, a differs) → cipher_variant (a+c match, b differs)
      → partial (b or c alone) → none
```

For a `cipher_variant` hit, if any of the matched a+c records is a known browser
(`application` contains Chrome/Firefox/Safari/Edge/Brave/Opera, or library is a
browser engine), attach a `browser_mimicry` note to the result. Surfaced in CLI
and web with a pivot hint ("same a+c, different cipher hash — possible cipher
randomization or impersonation").

`lookup()` return contract stays `(matches, match_type)`; for `cipher_variant`,
`matches` is a list of records (the a+c neighbors) and the browser-mimicry note
is attached to the formatting layer (computed from the records, not stored on
them).

### 4. Reverse metadata search (`JA4Lookup.search_metadata(term, field=None)`)

Case-insensitive substring across `application`, `library`, `device`, `os`,
`user_agent_string`, `notes` (or a single `field` if given). Returns matching
records including their fingerprints.

CLI: `--search TERM` with optional `--field application`. Web: a second search
box → `/search` route.

### 5. VirusTotal robustness

- `VirusTotalLookup.verify_key()` → `{"status": "no_key"|"invalid"|"valid"|"valid_no_intelligence", "message"}`.
  Uses a cheap authenticated endpoint to confirm the key, then probes whether
  `intelligence/search` is permitted (premium) vs not.
- CLI `--vt-check`: print the verification result and exit.
- Clearer messaging on 403 (free keys cannot run `behavior_network:` queries).
- Confirm env loading: both `VIRUSTOTAL_API_KEY` and `VT_API_KEY` honored;
  `load_dotenv()` runs before instantiation in both entry points.

### 6. Efficiency pass

Fold actionable wins into `_build_indexes` (single pass over the DB):
- Pre-parse each record's `ja4_a` once and stash the parsed structure +
  computed risk on a side table keyed by record id (not mutating source dicts),
  OR store parsed tuples in lightweight per-record cache used by `hunt`.
- Build the `(a,c)` index alongside the existing exact/cipher/extension indexes.

Result: `hunt`, `cipher_variant`, and risk filtering are one-pass / indexed
instead of re-parsing 73k records per call. Remaining observations (wildcard
full-scan cost, batch behavior) documented in the README efficiency notes.

### 7. Tests & README

- `tests/test_ja4lookr.py` (pytest, **no network** — inject a synthetic `_db`
  and pre-set `_indexes` via `_build_indexes`): `parse_ja4` field decoding;
  `assess_risk` for the four reference signatures + clean Chrome; all match
  tiers (exact / near / cipher_variant / partial / none); `hunt` filters;
  `search_metadata`; `wildcard_to_regex`; `defang`; `yara_rule_for`.
- Add `pytest` to `requirements.txt`.
- README: risk/flags section, hunting filters, reverse search, `cipher_variant`
  tier, VT key setup + `--vt-check`, ja4db-search comparison table, and a
  hunt.io-inspired "field guide" built around the four C2 signatures.

## Build approach

TDD per unit (tests against the synthetic DB first). All detection logic lives
in `ja4lookr.py` as the single source of truth; `app.py` and templates consume
the same functions. No new heavy dependencies.

## Out of scope (YAGNI)

- JA4X certificate parsing / JA4S/JA4H-specific decoders beyond what already
  exists in the DB fields.
- Live PCAP ingestion.
- Persisting computed risk back into the cached DB file.
