# JA4LookR

A JA4 fingerprint **threat-hunting** tool with CLI and Web interfaces. Pulls the
full [JA4DB](https://ja4db.com), caches it locally (refreshed **hourly**), and
resolves matches in-process — including **near**, **cipher-variant**, and
**partial** matches when an exact lookup misses. Every parsed fingerprint is
scored by a **risk engine** for the indicators threat hunters look for (legacy
TLS, IP-only handshakes, missing ALPN). Optionally pivots to VirusTotal
Intelligence for enrichment.

## Features

- **Risk engine** — every fingerprint is auto-scored `none → low → medium →
  high` for **legacy TLS**, **direct-to-IP / no SNI** (the `i` char), and
  **no ALPN** (`00`), with combo escalation for the classic C2 shape. Shown in
  both CLI and web. See [Risk engine](#risk-engine).
- **Database hunting** — sweep the whole JA4DB for risky structural patterns:
  `--hunt legacy-tls,no-sni,no-alpn,risky,quic` (CLI) or the **Hunt DB** tab
  (web). See [Hunting the database](#hunting-the-database).
- **Reverse metadata search** — find fingerprints *by* application / User-Agent
  / library / OS / device: `--search cobalt` (CLI) or the **Reverse Search**
  tab (web). The inverse of a JA4 lookup. See [Reverse search](#reverse-search).
- **Tiered matching** — exact → near (same cipher+extension hash, different
  `ja4_a`) → **cipher_variant** (same `ja4_a`+`ja4_c`, different cipher hash —
  catches cipher randomization & browser mimicry) → partial → none.
- **Local DB cache** — full JA4DB (~73k records, gzipped), auto-refreshed when
  older than **1 hour**. All lookups served from RAM.
- **Wildcard search** — `*` matches any section, e.g.
  `t13d190900_*_97f8aa674fd9` (GoLang/Sliver), `*_8daaf6152771_*`, `t13*`.
- **Fingerprint parser** — decodes every field of `ja4_a` with descriptions.
- **VirusTotal pivoting** — `--vt` runs `behavior_network:<fp>` and enriches the
  top hits with their **contacted IPs / domains / URLs** (defanged). Verify your
  key + privileges with `--vt-check`.
- **YARA scaffolding** — `--yara` emits a `vt` module rule (exact or regex).
- **JSON output by default** — full results written to a timestamped
  `ja4lookr_results_*.json` (`-o PATH` to rename, `-o -` to skip).
- **Batch + CSV** for pipelines, **Web UI + REST API** with rate limiting.
- **Tested** — `pytest` suite covering the parser, risk engine, all match
  tiers, hunting, and reverse search.

## What is JA4?

JA4 is a TLS client fingerprint developed by FoxIO. The full client fingerprint
has the layout:

```
ja4_a _ ja4_b _ ja4_c
```

| Section | Example      | Meaning                                                                  |
|---------|--------------|--------------------------------------------------------------------------|
| `ja4_a` | `t13d1516h2` | Transport + TLS version + SNI flag + cipher count + ext count + ALPN     |
| `ja4_b` | `8daaf6152771` | First 12 chars of SHA-256 over the sorted cipher suite list            |
| `ja4_c` | `b0da82dd1658` | First 12 chars of SHA-256 over sorted extensions + signature algorithms |

Decoding `ja4_a` (`t13d1516h2`):

| Position | Value | Meaning                                                |
|----------|-------|--------------------------------------------------------|
| `t`      | `t`   | Transport: `t` = TCP-TLS, `q` = QUIC, `d` = DTLS       |
| `13`     | `13`  | TLS version: `13`=1.3, `12`=1.2, `11`=1.1, `10`=1.0, `s3`/`s2`/`s1`=SSL |
| `d`      | `d`   | SNI flag: `d` = SNI present (domain), `i` = no SNI     |
| `15`     | 15    | Number of cipher suites offered (decimal, capped at 99)|
| `16`     | 16    | Number of TLS extensions present (decimal, capped at 99)|
| `h2`     | `h2`  | ALPN first/last char (`h2`=HTTP/2, `h1`=HTTP/1.1, `h3`=HTTP/3, `00`=none) |

Reference: [FoxIO-LLC/ja4](https://github.com/FoxIO-LLC/ja4)

## Risk engine

Every parsed fingerprint is scored for the indicators threat hunters look for.
Flags stack into an overall level (`none → low → medium → high`):

| Flag | Trigger | Severity | Why it matters |
|------|---------|----------|----------------|
| `legacy_tls` | TLS version `11`/`10`/`s3`/`s2`/`s1` | high | Pre-TLS-1.2 is rare for current legitimate clients; common in old malware, scanners, and embedded/IoT stacks. |
| `no_sni_ip` | SNI flag is `i` | medium | Connected to an IP with no server name. Browsers almost always send SNI; IP-only TLS is typical of C2 and custom tooling. |
| `no_alpn` | ALPN is `00` | medium | No application protocol negotiated. Alongside a browser-like handshake, suggests a minimal/custom TLS stack. |
| `quic` | Transport is `q` | info | TLS 1.3 in QUIC. Informational. |

**Combo escalation:** `no_sni_ip` **and** `no_alpn` together is the classic C2
shape and escalates the overall level to **high**.

Worked examples (from the FoxIO threat-hunting slides):

| Tool | JA4 | Risk | Why |
|------|-----|------|-----|
| Chrome 137 | `t13d1516h2_8daaf6152771_d8a2da3f94cd` | **none** | TLS 1.3, SNI present, ALPN `h2` |
| Cobalt Strike | `t12d210600_b973bfd88a0e_1da50ec048a3` | **medium** | TLS 1.2 + SNI, but no ALPN |
| Sliver | `t13i190800_9dc949149365_97f8aa674fd9` | **high** | IP-only **and** no ALPN |
| Metasploit | `t12i190700_d83cc789557e_16bbda4055b2` | **high** | IP-only **and** no ALPN |

In the web UI, the same explanation lives in the **About** panel on the home
page, and the risk panel is rendered with colour-coded severity on every result.

## Threat-hunting field guide

Inspired by the [hunt.io JA4 glossary](https://hunt.io/glossary/ja4-fingerprinting)
and the FoxIO/VirusTotal hunting workflow. Each technique has a CLI command and a
web equivalent.

- **Surface the risky shapes.** Sweep the DB for legacy TLS, IP-only, and
  no-ALPN clients:
  `python3 ja4lookr.py --hunt risky` · web: **Hunt DB** tab → tick *Risky*.
- **Partial-segment pivoting.** When an actor randomizes cipher suites, `ja4_a`
  and `ja4_c` stay stable while `ja4_b` changes. A lookup that misses exact/near
  but shares `ja4_a`+`ja4_c` with a known entry returns the **`cipher_variant`**
  tier — and if those neighbours are browsers, a **browser-mimicry** warning.
  Pivot wider with a wildcard on the cipher hash: `python3 ja4lookr.py "t13d1516h2_*_d8a2da3f94cd"`.
- **ALPN-00 non-browser heuristic.** `--hunt no-alpn` finds clients advertising
  no application protocol — with a browser-like handshake this points at a
  minimal/custom stack (malware or tooling).
- **Direct-to-IP C2.** `--hunt no-sni,no-alpn` isolates the IP-only + no-ALPN
  shape used by Sliver and Metasploit.
- **Reverse-pivot from intel.** Got a tool name from a report? Find its known
  fingerprints: `python3 ja4lookr.py --search "cobalt strike"`.
- **Pivot to infrastructure.** Feed a fingerprint (or a `t13d190900_*_97f8aa674fd9`
  wildcard) to VirusTotal: `python3 ja4lookr.py --vt "t13i190800_*_97f8aa674fd9"`
  to surface communicating files and their contacted IPs/domains/URLs.

## Comparison to sans-blue-team/ja4db-search

[`ja4db-search`](https://github.com/sans-blue-team/ja4db-search) is a handy
minimal lookup. JA4LookR is a superset:

| Capability | ja4db-search | JA4LookR |
|------------|:---:|:---:|
| Exact `ja4_fingerprint` lookup | ✓ | ✓ |
| Near / partial / **cipher_variant** matching | — | ✓ |
| Wildcard hunting patterns | — | ✓ |
| Risk scoring (legacy TLS / IP-only / no-ALPN) | — | ✓ |
| Structural DB hunting (`--hunt`) | — | ✓ |
| Reverse metadata search (by app/UA/library) | — | ✓ |
| Auto-cached DB, hourly refresh | manual file | ✓ |
| VirusTotal pivot + enrichment | — | ✓ |
| YARA scaffolding | — | ✓ |
| Web UI + REST API | — | ✓ |

## Installation

```bash
git clone https://github.com/yourusername/ja4LookR.git
cd ja4LookR
pip3 install -r requirements.txt
```

### Optional: VirusTotal Integration

`--vt` performs the JA4 hunt described in the
[FoxIO + VirusTotal blog post](https://blog.virustotal.com/2024/10/unveiling-hidden-connections-ja4-client.html):

1. **`behavior_network:<ja4>`** — find all files in VT that exhibit this JA4
   in their dynamic-analysis network behavior.
2. For the top N file results, automatically pull
   `/files/<sha>/contacted_ips`, `contacted_domains`, and `contacted_urls`,
   then aggregate them so the top C2/CDN/host pivots surface immediately.
3. Wildcards in the JA4 (`t13d190900_*_97f8aa674fd9`) are passed straight
   through to the VT search.

Requires a VT **Intelligence** or **Enterprise** API key — the free public
API rejects `behavior_network:` (returns 403/empty). Provide the key via:

```bash
# .env file in the project root, or shell environment
VIRUSTOTAL_API_KEY=your_vt_intelligence_key_here
# VT_API_KEY is also accepted as an alias
```

The key is read from the environment (or a `.env` file in the project root) by
both the CLI and the web app. Verify it before hunting:

```bash
python3 ja4lookr.py --vt-check
# VirusTotal key: valid — Key valid; VT Intelligence (behavior_network) available
# VirusTotal key: valid_no_intelligence — Key valid but lacks VT Intelligence; ...
# VirusTotal key: no_key — No VT API key set (VIRUSTOTAL_API_KEY or VT_API_KEY)
```

VT enrichment costs ~3 API calls per enriched file (default 5 files = ~16
calls per lookup). Tune with `--vt-max-enrich` / `--vt-max-files`, or skip
enrichment entirely with `--no-vt-enrich`.

## Usage

### Web Interface

Start the web server:

```bash
# Development server (localhost only - secure by default)
python3 app.py

# Production server on localhost (recommended - use reverse proxy for network access)
gunicorn -w 4 -b 127.0.0.1:5000 app:app

# Or using waitress (Windows-friendly)
waitress-serve --host=127.0.0.1 --port=5000 app:app
```

**Security Note:** The application binds to `127.0.0.1` (localhost only) by default. For network access, use a reverse proxy like nginx or Apache with proper SSL/TLS configuration.

Then open your browser to `http://localhost:5000`

**Web Features (full parity with the CLI):**
- Single fingerprint or **wildcard pattern** lookup (e.g. `t13d190900_*_97f8aa674fd9`)
- Match-type rendering: Exact / Near / **Cipher variant** / Wildcard / Partial / Not Found
- Decoded JA4 components plus a colour-coded **risk panel** (legacy TLS, IP-only,
  no-ALPN), with the **About** panel explaining how the risk engine works
- **Hunt DB** tab — checkbox-driven structural hunting (legacy TLS / no SNI /
  no ALPN / QUIC / risky)
- **Reverse Search** tab — find fingerprints by application / User-Agent / metadata
- Browser-mimicry warning on cipher-variant hits
- VirusTotal pivot with per-file **contacted IPs / domains / URLs (defanged)**
- Inline **YARA rule** scaffold with copy-to-clipboard
- One-click **JSON export** of the full result payload
- Batch lookup (up to 100 fingerprints, wildcards accepted)
- Responsive design for mobile and desktop

### CLI Interface

The CLI shares the same engine as the web app — every match type, VirusTotal
pivot, network enrichment, YARA scaffold, and JSON output is available in
both. Pick whichever feels better for the moment; nothing is locked away.

First run downloads the full JA4DB (~73k records, ~16s) and gzip-caches it
under `.ja4_cache/ja4db_full.json.gz`. Subsequent runs load from disk in
under a second.

#### Single Lookup

```bash
python3 ja4lookr.py t13d1516h2_8daaf6152771_b0da82dd1658
```

Output classifies the result as `exact`, `near`, `partial`, or `not found`.
A near match means the cipher+extension hashes are identical to a known
sample but `ja4_a` differs (typically a different ALPN, SNI flag, or
cipher/extension count).

#### Parse Fingerprint Structure

```bash
python3 ja4lookr.py --parse t13d1516h2_8daaf6152771_b0da82dd1658
```

Returns labeled JSON for every field — transport, TLS version, SNI flag,
cipher/extension counts, ALPN — plus the two SHA-256 truncations.

#### Wildcard / Hunting Search

```bash
# Match the article's GoLang / Sliver Agent example
python3 ja4lookr.py "t13d190900_*_97f8aa674fd9"

# Anything sharing this cipher hash
python3 ja4lookr.py "*_8daaf6152771_*"

# Same JA4_A + JA4_C, any cipher (used in VT searches too)
python3 ja4lookr.py --vt "t10d070600_*_1a3805c3aa63"
```

#### Hunting the database

Sweep the entire JA4DB for risky structural patterns — no fingerprint needed.
Criteria are comma-separated and **ANDed** together:

```bash
# Every legacy-TLS client in the DB
python3 ja4lookr.py --hunt legacy-tls

# The IP-only + no-ALPN C2 shape (Sliver / Metasploit)
python3 ja4lookr.py --hunt no-sni,no-alpn

# Anything the risk engine rates medium or high
python3 ja4lookr.py --hunt risky

# Compose with existing filters
python3 ja4lookr.py --hunt no-alpn -a "Cobalt Strike" --verified-only
```

Criteria: `legacy-tls`, `no-sni`, `no-alpn`, `risky`, `quic`. Web equivalent:
the **Hunt DB** tab.

#### Reverse search

Find fingerprints *by* their metadata — the inverse of a JA4 lookup:

```bash
# Search all metadata fields (application, UA, library, device, os, notes)
python3 ja4lookr.py --search "cobalt strike"

# Restrict to one field
python3 ja4lookr.py --search curl --field user_agent_string
```

Web equivalent: the **Reverse Search** tab.

#### VirusTotal Pivot

```bash
# Requires VIRUSTOTAL_API_KEY env var (Intelligence/Enterprise key)
python3 ja4lookr.py --vt t13d1516h2_8daaf6152771_b0da82dd1658

# Lighter version, no per-file network enrichment
python3 ja4lookr.py --vt --no-vt-enrich <fp>

# Cap files / enrichment for quota control
python3 ja4lookr.py --vt --vt-max-files 5 --vt-max-enrich 2 <fp>
```

#### YARA Rule Scaffolding

```bash
# Exact-match rule
python3 ja4lookr.py --yara t10d070600_c50f5591e341_1a3805c3aa63

# Regex rule from a wildcard pattern
python3 ja4lookr.py --yara "t10d070600_*_1a3805c3aa63"
```

#### JSON File Output (default)

By default a JSON results file is written to `ja4lookr_results.json` next
to your invocation, containing parsed components, JA4DB matches, VT pivot
data (when `--vt`), and the YARA rule (when `--yara`).

```bash
python3 ja4lookr.py <fp>                       # writes ja4lookr_results.json
python3 ja4lookr.py <fp> -o investigation.json # custom path
python3 ja4lookr.py <fp> -o -                  # disable file output
python3 ja4lookr.py <fp> --json                # also dump JSON to stdout
```

#### Batch Lookup from File

```bash
python3 ja4lookr.py -f fingerprints.txt
python3 ja4lookr.py -f fingerprints.txt --csv > results.csv
python3 ja4lookr.py -f fingerprints.txt --verified-only
python3 ja4lookr.py -f fingerprints.txt -a "Chrome"
```

#### Cache Control

```bash
python3 ja4lookr.py --refresh <fp>     # force redownload of JA4DB
python3 ja4lookr.py --no-cache <fp>    # bypass disk cache (slow)
```

#### JSON Output

```bash
python3 ja4lookr.py --json <fp>
```

### REST API

The web server provides a REST API for programmatic access:

```bash
# Lookup a fingerprint
curl http://localhost:5000/api/lookup/t13d1516h2_8daaf6152771_b0da82dd1658

# Health check
curl http://localhost:5000/health
```

Optional query parameters:
- `vt=1` — also run the VirusTotal Intelligence pivot (needs `VIRUSTOTAL_API_KEY`)
- `enrich=1` — when `vt=1`, fetch contacted IPs/domains/URLs per file (default on)

**Response Format:**

```json
{
  "fingerprint": "t13d1516h2_8daaf6152771_b0da82dd1658",
  "match_type": "near",
  "matches": [{ "ja4_fingerprint": "t13d1517h2_8daaf6152771_b0da82dd1658",
                "user_agent_string": "Mozilla/5.0 ... Chrome/125.0.0.0 ...",
                "verified": false, "observation_count": 6 }],
  "parsed": {
    "ja4_a": "t13d1516h2",
    "ja4_b_cipher_hash": "8daaf6152771",
    "ja4_c_extension_hash": "b0da82dd1658",
    "components": {
      "transport":       { "code": "t",  "meaning": "TCP (TLS over TCP)" },
      "tls_version":     { "code": "13", "meaning": "TLS 1.3" },
      "sni":             { "code": "d",  "meaning": "SNI present (server hostname sent in ClientHello)" },
      "cipher_count":    { "code": "15", "value": 15, "meaning": "15 cipher suites offered" },
      "extension_count": { "code": "16", "value": 16, "meaning": "16 TLS extensions present" },
      "alpn":            { "code": "h2", "meaning": "HTTP/2" }
    },
    "summary": "TCP (TLS over TCP) | TLS 1.3 | SNI present | 15 ciphers, 16 extensions | ALPN=HTTP/2"
  },
  "timestamp": "2026-05-07T12:34:56"
}
```

## Security Features

- **Rate Limiting**:
  - Web: 50 requests/hour, 200/day per IP
  - Single lookup: 30/minute
  - Batch lookup: 10/minute
  - API: 60/minute
- **Input Validation**: All fingerprints validated before lookup
- **Batch Size Limits**: Maximum 100 fingerprints per batch
- **CSRF Protection**: Enabled for all forms
- **Error Handling**: Secure error messages without information leakage

## Performance Notes

- **Single bulk pull** of JA4DB instead of per-fingerprint HTTP. The public
  `?ja4_fingerprint=` filter only honors exact matches; partial filters
  (`__contains`, `__endswith`) are ignored, so per-request lookups can never
  produce near/partial matches. Local indexing solves both problems.
- **In-memory indexes** built in a **single pass** over the DB:
  `exact`, `cipher`, `extension`, the `(ja4_a, ja4_c)` index (for the
  `cipher_variant` tier), and a `struct` cache of pre-parsed components + risk
  (for `--hunt`). 73k-record lookups and hunts are sub-millisecond after the
  one-time build; nothing is re-parsed per query.
- **gzip on disk** keeps the cache around 5–10 MB.
- **Wildcard search is a full scan** of the DB by design (regex over every
  fingerprint field) — still fast on 73k records, but not indexed.

## Configuration

### Environment Variables

```bash
# JA4DB cache (no key required)
# Cache lives at .ja4_cache/ja4db_full.json.gz, auto-refreshed when older than 1 hour.

# VirusTotal Intelligence (optional, only used with --vt)
VIRUSTOTAL_API_KEY=your_key_here   # or VT_API_KEY

# Flask secret key (change in production!)
SECRET_KEY="your-secure-random-key-here"
```

### Production Deployment

**IMPORTANT SECURITY NOTES:**
- The application binds to `127.0.0.1` (localhost only) by default
- **Never bind directly to 0.0.0.0** - always use a reverse proxy with SSL/TLS
- For network access, use nginx/Apache as a reverse proxy with HTTPS

For production use:

1. **Change the Flask secret key** in `app.py` (CRITICAL!)
2. **Use a production WSGI server** (gunicorn, waitress, uWSGI)
3. **Set up reverse proxy** (nginx, Apache) with SSL/TLS
4. **Keep binding to 127.0.0.1** (localhost only)
5. **Configure proper logging**
6. **Set up monitoring**

Example with gunicorn (localhost binding):

```bash
gunicorn -w 4 \
         -b 127.0.0.1:5000 \
         --access-logfile access.log \
         --error-logfile error.log \
         --log-level info \
         app:app
```

Example nginx configuration with SSL:

```nginx
server {
    listen 443 ssl http2;
    server_name ja4lookr.example.com;

    ssl_certificate /path/to/cert.pem;
    ssl_certificate_key /path/to/key.pem;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers HIGH:!aNULL:!MD5;

    location / {
        proxy_pass http://127.0.0.1:5000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}

# Redirect HTTP to HTTPS
server {
    listen 80;
    server_name ja4lookr.example.com;
    return 301 https://$server_name$request_uri;
}
```

## Examples

### Example 1: Identify Unknown Traffic

```bash
python3 ja4lookr.py t13d1516h2_8daaf6152771_b0da82dd1658

# [~] Near match: same cipher+extension hash, different ja4_a (16 records)
#    User-Agent: Mozilla/5.0 ... Chrome/125.0.0.0 ...
#    App:        Chromium Browser (verified)
# Same client family as Chromium 125 — the ja4_a differs only in extension count,
# typical of slightly different Chrome builds/profiles.
```

### Example 1b: Hunt with a Wildcard

```bash
python3 ja4lookr.py "t13d190900_*_97f8aa674fd9"

# [*] Wildcard match in JA4DB (3 records)
#    Library: GoLang  (verified)
#    App:     Sliver Agent  (verified)
#    App:     Sliver Agent  (verified)
# Matches the JA4 fingerprint pattern from the FoxIO/VT blog —
# any GoLang TLS stack with this extension hash, including Sliver C2.
```

### Example 2: Batch Investigation

```bash
# You have 50 suspicious fingerprints from your SIEM
python3 ja4lookr.py -f suspicious_fingerprints.txt --csv > investigation.csv

# Open investigation.csv to see which are known apps vs unknown threats
```

### Example 3: Automated Monitoring

```bash
#!/bin/bash
# Monitor new fingerprints and alert on unknowns

while read fingerprint; do
    result=$(python3 ja4lookr.py "$fingerprint" 2>&1)
    if echo "$result" | grep -q "Not found"; then
        echo "ALERT: Unknown fingerprint detected: $fingerprint"
        # Send alert to your monitoring system
    fi
done < new_fingerprints.txt
```

## CLI Options Reference

```
usage: ja4lookr.py [-h] [-f FILE] [-a APPLICATION] [--verified-only]
                   [--no-cache] [--refresh] [--parse] [--csv]
                   [--vt] [--no-vt-enrich] [--vt-max-enrich N]
                   [--vt-max-files N] [--yara] [--hunt CRITERIA]
                   [--search TERM] [--field FIELD] [--vt-check]
                   [--json] [-o OUTPUT] [fingerprint]

positional arguments:
  fingerprint           JA4/JA4S/JA4H fingerprint or wildcard pattern
                        (use * to wildcard a section)

options:
  -f, --file FILE       File with fingerprints (one per line)
  -a, --application     Filter results by application name
  --verified-only       Show only verified entries
  --no-cache            Disable local DB cache
  --refresh             Force refresh of local JA4DB cache
  --parse               Parse fingerprint structure with field descriptions
  --csv                 Print CSV (batch mode)
  --vt                  Run VirusTotal Intelligence pivot
                        (behavior_network:<fp> + contacted IPs/domains/URLs)
  --no-vt-enrich        Skip per-file network enrichment in VT
  --vt-max-enrich N     Max files to enrich (default: 5)
  --vt-max-files N      Max files to return from VT search (default: 10)
  --yara                Print VT YARA rule scaffold (regex when wildcarded)
  --hunt CRITERIA       Hunt the JA4DB by structural criteria, no fingerprint
                        needed. Comma-separated: legacy-tls,no-sni,no-alpn,risky,quic
  --search TERM         Reverse lookup by metadata substring
  --field FIELD         Restrict --search to one field (e.g. application)
  --vt-check            Verify the VirusTotal API key/privileges and exit
  --json                Print full result JSON to stdout
  -o, --output PATH     JSON output file (default: ja4lookr_results_<ts>.json,
                        use - to skip)
```

### Match Types

| Type             | Meaning                                                             |
|------------------|---------------------------------------------------------------------|
| `exact`          | Fingerprint matches a stored `ja4*` value verbatim.                 |
| `near`           | Cipher hash AND extension hash match, but `ja4_a` differs (e.g. different ALPN, SNI flag, or count). Strong signal it's the same client family. |
| `cipher_variant` | Same `ja4_a` AND `ja4_c`, different cipher hash (`ja4_b`). Indicates cipher-suite randomization; if neighbours are browsers, flags possible **mimicry/impersonation**. |
| `wildcard`       | Pattern (containing `*`) matched one or more records.               |
| `partial`        | Only the cipher hash OR only the extension hash matches known records. Weaker — useful for narrowing the client library / ecosystem. |
| `none`           | Nothing matches. Consider `--hunt`, `--vt`, or threat-intel pivots. |

## Testing

```bash
pip3 install -r requirements.txt   # includes pytest
python3 -m pytest -v
```

The suite runs fully offline — it injects a synthetic in-memory DB, so no
network or live JA4DB is required. It covers the parser, the risk engine (all
four reference signatures), every match tier, hunting, reverse search,
wildcards, defang, and YARA generation.

## Troubleshooting

### Web interface won't start

```bash
# Check if port 5000 is already in use
lsof -i :5000

# Use a different port
python3 app.py --port 8080
```

### Rate limit errors

The tool implements rate limiting to prevent abuse. If you hit limits:
- Wait a few minutes and try again
- Use the CLI tool for batch operations
- Contact the maintainer for higher limits

### Cache issues

```bash
# Clear the local JA4DB cache
rm -rf .ja4_cache/

# Force refresh on next run
python3 ja4lookr.py --refresh <fingerprint>

# Or bypass cache entirely (re-pulls 73k records every run)
python3 ja4lookr.py --no-cache <fingerprint>
```

### VirusTotal returns 403 / "not available on this key"

`behavior_network:` search needs a paid VT Intelligence or Enterprise key.
The free public API will return 403 / empty results. Run `python3 ja4lookr.py
--vt-check` to confirm whether your key has Intelligence privileges — a
`valid_no_intelligence` result means the key works but can't run
`behavior_network:` queries. Either upgrade the key or remove `--vt`.

## Contributing

Contributions welcome! Please:
1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Submit a pull request

## License

MIT License - See LICENSE file for details

## Acknowledgments

- [JA4+ Network Fingerprinting](https://github.com/FoxIO-LLC/ja4) by FoxIO
- [JA4DB](https://ja4db.com) - The fingerprint database

## Support

For issues, questions, or suggestions:
- Open an issue on GitHub
- Check existing issues for solutions
- Review the documentation

---

**Note**: This tool queries the public JA4DB API. Please use responsibly and respect their rate limits.
