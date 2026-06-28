#!/usr/bin/env python3
"""JA4 Fingerprint Lookup Tool.

Pulls the full JA4DB once and caches it locally, then resolves exact, near,
partial, or wildcard matches in-process. Falls back to VirusTotal Intelligence
with automatic file/network pivoting when a sample is unfamiliar.

References:
  https://github.com/FoxIO-LLC/ja4
  https://blog.virustotal.com/2024/10/unveiling-hidden-connections-ja4-client.html
"""
import argparse
import gzip
import json
import os
import re
import sys
from collections import Counter
from datetime import datetime, timedelta
from pathlib import Path

import requests

try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass


JA4DB_URL = "https://ja4db.com/api/read/"
DEFAULT_CACHE_DIR = Path(".ja4_cache")
DB_CACHE_NAME = "ja4db_full.json.gz"
DB_CACHE_MAX_AGE = timedelta(hours=1)
DEFAULT_OUTPUT_PREFIX = "ja4lookr_results"


def default_output_path():
    """Timestamped default filename so successive runs don't overwrite."""
    ts = datetime.now().strftime("%Y%m%dT%H%M%S")
    return f"{DEFAULT_OUTPUT_PREFIX}_{ts}.json"


# ----- JA4 spec decoding -----
TRANSPORT = {
    "t": "TCP (TLS over TCP)",
    "q": "QUIC (TLS 1.3 carried in QUIC)",
    "d": "DTLS",
}
TLS_VERSIONS = {
    "13": "TLS 1.3",
    "12": "TLS 1.2",
    "11": "TLS 1.1",
    "10": "TLS 1.0",
    "s3": "SSL 3.0",
    "s2": "SSL 2.0",
    "s1": "SSL 1.0",
    "00": "Unknown / no TLS",
}
SNI_FLAG = {
    "d": "SNI present (server hostname sent in ClientHello)",
    "i": "No SNI (IP-only / hostname omitted)",
}
ALPN_KNOWN = {
    "h2": "HTTP/2",
    "h1": "HTTP/1.1",
    "h3": "HTTP/3",
    "00": "no ALPN advertised",
}

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


def parse_ja4(fingerprint):
    """Decode a JA4 client fingerprint into labeled, human-readable components.

    Layout of the first segment (ja4_a):
      [transport][tls_version 2c][sni 1c][cipher_count 2d][ext_count 2d][alpn 2c]
      e.g. t13d1516h2 = TCP, TLS 1.3, SNI present, 15 ciphers, 16 extensions, ALPN h2
    Followed by:
      ja4_b = first 12 chars of SHA256 over the sorted cipher list
      ja4_c = first 12 chars of SHA256 over sorted extensions + signature algorithms
    """
    if "*" in fingerprint:
        return None
    parts = fingerprint.split("_")
    if len(parts) != 3 or len(parts[0]) < 10:
        return None
    a, b, c = parts
    transport, tls_ver, sni = a[0], a[1:3], a[3]
    cipher_code, ext_code, alpn = a[4:6], a[6:8], a[8:10]
    try:
        cipher_n, ext_n = int(cipher_code), int(ext_code)
    except ValueError:
        cipher_n = ext_n = None

    return {
        "fingerprint": fingerprint,
        "ja4_a": a,
        "ja4_b_cipher_hash": b,
        "ja4_c_extension_hash": c,
        "components": {
            "transport": {"code": transport,
                          "meaning": TRANSPORT.get(transport, f"Unknown ({transport})")},
            "tls_version": {"code": tls_ver,
                            "meaning": TLS_VERSIONS.get(tls_ver, f"Unknown ({tls_ver})")},
            "sni": {"code": sni,
                    "meaning": SNI_FLAG.get(sni, f"Unknown ({sni})")},
            "cipher_count": {"code": cipher_code, "value": cipher_n,
                             "meaning": f"{cipher_n} cipher suites offered"
                             if cipher_n is not None else "unparsed"},
            "extension_count": {"code": ext_code, "value": ext_n,
                                "meaning": f"{ext_n} TLS extensions present"
                                if ext_n is not None else "unparsed"},
            "alpn": {"code": alpn,
                     "meaning": ALPN_KNOWN.get(alpn, f"ALPN first/last char = '{alpn}'")},
        },
        "summary": (
            f"{TRANSPORT.get(transport, transport)} | "
            f"{TLS_VERSIONS.get(tls_ver, tls_ver)} | "
            f"{SNI_FLAG.get(sni, sni)} | "
            f"{cipher_n} ciphers, {ext_n} extensions | "
            f"ALPN={ALPN_KNOWN.get(alpn, alpn)}"
        ),
        "risk": assess_risk(transport, tls_ver, sni, alpn, cipher_n, ext_n),
        "is_tls13": tls_ver == "13",
        "is_tls12": tls_ver == "12",
        "is_quic": transport == "q",
    }


# ----- Wildcard helpers -----
def has_wildcard(fp):
    return "*" in fp


def defang(value):
    """Defang an IP / domain / URL so it can't be accidentally clicked.

    http://evil.com/x -> hxxp://evil[.]com/x
    1.2.3.4           -> 1.2.3[.]4
    """
    if not isinstance(value, str):
        return value
    out = value.replace("https://", "hxxps://").replace("http://", "hxxp://")
    return out.replace(".", "[.]")


BROWSER_HINTS = ("chrome", "chromium", "firefox", "safari", "edge",
                 "brave", "opera")


def is_browser_record(r):
    """True if a JA4DB record looks like a mainstream web browser."""
    blob = " ".join(str(r.get(k) or "") for k in
                    ("application", "library", "user_agent_string")).lower()
    return any(h in blob for h in BROWSER_HINTS)


def wildcard_to_regex(pattern):
    """Convert a JA4 wildcard pattern to a compiled regex. `*` matches any chars."""
    escaped = re.escape(pattern).replace(r"\*", ".*")
    return re.compile(f"^{escaped}$", re.IGNORECASE)


# ----- JA4DB lookup (local cache + in-memory indexes) -----
class JA4Lookup:
    FP_FIELDS = ("ja4_fingerprint", "ja4s_fingerprint", "ja4h_fingerprint",
                 "ja4x_fingerprint", "ja4t_fingerprint", "ja4ts_fingerprint",
                 "ja4tscan_fingerprint")

    def __init__(self, cache_dir=DEFAULT_CACHE_DIR, max_age=DB_CACHE_MAX_AGE):
        self.cache_dir = Path(cache_dir) if cache_dir else None
        if self.cache_dir:
            self.cache_dir.mkdir(parents=True, exist_ok=True)
        self.cache_duration = max_age
        self._db = None
        self._indexes = None

    def _db_path(self):
        return self.cache_dir / DB_CACHE_NAME if self.cache_dir else None

    def _cache_fresh(self):
        path = self._db_path()
        if not path or not path.exists():
            return False
        mtime = datetime.fromtimestamp(path.stat().st_mtime)
        return datetime.now() - mtime < self.cache_duration

    def refresh(self, force=False):
        path = self._db_path()
        if path and not force and self._cache_fresh():
            return
        print(f"[*] Pulling JA4DB from {JA4DB_URL} ...", file=sys.stderr)
        resp = requests.get(JA4DB_URL, timeout=120)
        resp.raise_for_status()
        data = resp.json()
        print(f"[*] {len(data)} records cached", file=sys.stderr)
        if path:
            with gzip.open(path, "wt", encoding="utf-8") as f:
                json.dump(data, f)
        self._db = data
        self._indexes = None

    def _load(self):
        if self._db is not None:
            return
        path = self._db_path()
        if path and self._cache_fresh():
            with gzip.open(path, "rt", encoding="utf-8") as f:
                self._db = json.load(f)
        else:
            self.refresh(force=True)

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

    def lookup(self, fingerprint):
        """Return (matches, match_type).
        match_type: exact | near | partial | wildcard | none.
        For partial, matches is dict {cipher_matches, extension_matches}; otherwise list.
        """
        self._load()
        self._build_indexes()
        fp = fingerprint.lower().strip()

        if has_wildcard(fp):
            rx = wildcard_to_regex(fp)
            seen, hits = set(), []
            for r in self._db:
                for field in self.FP_FIELDS:
                    v = r.get(field)
                    if v and rx.match(v):
                        oid = id(r)
                        if oid not in seen:
                            seen.add(oid)
                            hits.append(r)
                        break
            return hits, ("wildcard" if hits else "none")

        hits = self._indexes["exact"].get(fp)
        if hits:
            return hits, "exact"

        if fp.count("_") != 2:
            return [], "none"
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

    def batch_lookup(self, fingerprints, show_progress=True):
        results = {}
        self._load()
        self._build_indexes()
        total = len(fingerprints)
        for idx, fp in enumerate(fingerprints, 1):
            if show_progress:
                print(f"[{idx}/{total}] {fp}", end="\r", file=sys.stderr)
            results[fp] = self.lookup(fp)
        if show_progress:
            print(file=sys.stderr)
        return results


# ----- VirusTotal Intelligence pivoting -----
class VirusTotalLookup:
    """VT Intelligence pivoting on JA4.

    Implements the workflow from FoxIO + VirusTotal:
      1. behavior_network:<ja4>           - find files communicating with this JA4
         (wildcards supported, e.g. behavior_network:t13d190900_*_97f8aa674fd9)
      2. /files/<sha256>/contacted_{ips,domains,urls} - enrich each hit with
         the network indicators those samples reach out to
      3. Generate a VT YARA rule scaffold for hunting

    Requires a VT Intelligence or Enterprise API key. The free public key
    rejects behavior_network: queries with 403/empty.
    """

    def __init__(self, api_key=None):
        self.api_key = api_key or os.getenv("VIRUSTOTAL_API_KEY") or os.getenv("VT_API_KEY")
        self.base_url = "https://www.virustotal.com/api/v3"
        self.session = requests.Session()
        if self.api_key:
            self.session.headers["x-apikey"] = self.api_key

    def is_configured(self):
        return bool(self.api_key)

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

    def _get(self, path, params=None, timeout=20):
        r = self.session.get(f"{self.base_url}{path}", params=params, timeout=timeout)
        if r.status_code == 401:
            raise PermissionError("Invalid VirusTotal API key")
        if r.status_code == 403:
            raise PermissionError("VT Intelligence not available on this key (paid feature)")
        if r.status_code == 429:
            raise RuntimeError("VirusTotal rate limit exceeded")
        r.raise_for_status()
        return r.json()

    def search_behavior_network(self, ja4_or_pattern, limit=25):
        """Run intelligence search: behavior_network:<ja4_or_wildcard>."""
        data = self._get("/intelligence/search",
                         params={"query": f"behavior_network:{ja4_or_pattern}",
                                 "limit": limit})
        return data.get("data", [])

    def get_file_network(self, sha256, limit=10):
        """Pull contacted IPs / domains / URLs for one file. Values are defanged."""
        out = {}
        for endpoint, key in (("contacted_ips", "contacted_ips"),
                              ("contacted_domains", "contacted_domains"),
                              ("contacted_urls", "contacted_urls")):
            try:
                data = self._get(f"/files/{sha256}/{endpoint}", params={"limit": limit})
                items = data.get("data", [])
                if endpoint == "contacted_urls":
                    raw = [(it.get("attributes", {}).get("url") or it.get("id"))
                           for it in items]
                else:
                    raw = [it.get("id") for it in items]
                out[key] = [defang(v) for v in raw if v]
            except (PermissionError, RuntimeError, requests.exceptions.RequestException) as e:
                out[key] = {"error": str(e)}
        return out

    def lookup_ja4(self, ja4_or_pattern, enrich=True, max_enrich=5,
                   max_files=10, network_limit=10):
        if not self.is_configured():
            return {"status": "not_configured",
                    "message": "Set VIRUSTOTAL_API_KEY (or VT_API_KEY) to enable VT lookup"}
        query = f"behavior_network:{ja4_or_pattern}"
        try:
            files = self.search_behavior_network(ja4_or_pattern, limit=max(max_files, 25))
        except PermissionError as e:
            return {"status": "error", "query": query, "message": str(e)}
        except RuntimeError as e:
            return {"status": "error", "query": query, "message": str(e)}
        except requests.exceptions.RequestException as e:
            return {"status": "error", "query": query, "message": str(e)}

        if not files:
            return {"status": "not_found", "query": query,
                    "message": "No files in VT exhibit this JA4 in their behavior_network"}

        results = []
        all_ips, all_domains, all_urls = Counter(), Counter(), Counter()
        for idx, f in enumerate(files[:max_files]):
            a = f.get("attributes", {})
            stats = a.get("last_analysis_stats", {})
            sha = a.get("sha256")
            names = a.get("names") or []
            entry = {
                "sha256": sha,
                "name": a.get("meaningful_name") or (names[0] if names else "Unknown"),
                "type": a.get("type_description"),
                "size": a.get("size"),
                "malicious": stats.get("malicious", 0),
                "suspicious": stats.get("suspicious", 0),
                "undetected": stats.get("undetected", 0),
                "first_seen": a.get("first_submission_date"),
                "last_seen": a.get("last_analysis_date"),
                "tags": a.get("tags"),
                "vt_link": f"https://www.virustotal.com/gui/file/{sha}" if sha else None,
            }
            if enrich and sha and idx < max_enrich:
                net = self.get_file_network(sha, limit=network_limit)
                entry["network"] = net
                for ip in net.get("contacted_ips", []) or []:
                    if isinstance(ip, str):
                        all_ips[ip] += 1
                for d in net.get("contacted_domains", []) or []:
                    if isinstance(d, str):
                        all_domains[d] += 1
                for u in net.get("contacted_urls", []) or []:
                    if isinstance(u, str):
                        all_urls[u] += 1
            results.append(entry)

        summary = {
            "top_contacted_ips": all_ips.most_common(10),
            "top_contacted_domains": all_domains.most_common(10),
            "top_contacted_urls": all_urls.most_common(10),
        } if enrich else None

        return {
            "status": "found",
            "query": query,
            "count": len(results),
            "results": results,
            "network_pivots": summary,
        }


# ----- YARA rule scaffolding -----
def yara_rule_for(fingerprint):
    """Generate a VT YARA rule from a JA4 fingerprint or wildcard pattern.

    Pattern based on the FoxIO/VirusTotal blog post on JA4 hunting.
    Adjust the vt module field names for your environment if needed.
    """
    safe = re.sub(r"[^A-Za-z0-9_]", "_", fingerprint)
    rule_name = f"JA4_{safe}"[:80]
    if has_wildcard(fingerprint):
        regex = "/" + fingerprint.replace("*", ".*") + "/"
        condition = (f"        for any net in vt.behaviour.network : (\n"
                     f"            net.ja4 matches {regex}\n"
                     f"        )")
    else:
        condition = (f'        for any net in vt.behaviour.network : (\n'
                     f'            net.ja4 == "{fingerprint}"\n'
                     f'        )')
    return (
        f'import "vt"\n\n'
        f'rule {rule_name} {{\n'
        f'    meta:\n'
        f'        author = "ja4lookr"\n'
        f'        description = "Detect JA4 fingerprint {fingerprint}"\n'
        f'    condition:\n'
        f'{condition}\n'
        f'}}\n'
    )


# ----- Output formatting -----
RECORD_LABELS = [
    ("application", "App"),
    ("library", "Library"),
    ("device", "Device"),
    ("os", "OS"),
    ("user_agent_string", "User-Agent"),
    ("certificate_authority", "CA"),
    ("verified", "Verified"),
    ("observation_count", "Observations"),
    ("notes", "Notes"),
]


def _record_lines(r, indent="   "):
    for k, label in RECORD_LABELS:
        v = r.get(k)
        if v in (None, "", False) and k != "verified":
            continue
        yield f"{indent}{label:<13} {v}"


def _top_apps(records, n=5):
    counts = Counter()
    for r in records:
        label = r.get("application") or r.get("library")
        if not label and r.get("user_agent_string"):
            label = r["user_agent_string"][:60]
        if label:
            counts[label] += 1
    if not counts:
        return "no labeled records"
    return ", ".join(f"{name} ({c})" for name, c in counts.most_common(n))


def format_lookup(fp, matches, mt, app_filter=None, verified_only=False):
    def _filter(records):
        if app_filter:
            records = [r for r in records
                       if (r.get("application") or "").lower() == app_filter.lower()]
        if verified_only:
            records = [r for r in records if r.get("verified")]
        return records

    lines = [f"\nFingerprint: {fp}"]
    if mt == "exact":
        records = _filter(matches)
        lines.append(f"[OK] Exact match in JA4DB ({len(records)} record(s))")
        for r in records:
            lines.append("---")
            lines.extend(_record_lines(r))
    elif mt == "near":
        records = _filter(matches)
        lines.append(f"[~] Near match: same cipher+extension hash, different ja4_a "
                     f"({len(records)} record(s))")
        for r in records:
            lines.append("---")
            lines.append(f"   ja4           {r.get('ja4_fingerprint')}")
            lines.extend(_record_lines(r))
    elif mt == "wildcard":
        records = _filter(matches)
        lines.append(f"[*] Wildcard match in JA4DB ({len(records)} record(s))")
        for r in records[:25]:
            lines.append("---")
            lines.append(f"   ja4           {r.get('ja4_fingerprint')}")
            lines.extend(_record_lines(r))
        if len(records) > 25:
            lines.append(f"   ... {len(records) - 25} more (full list in JSON output)")
    elif mt == "partial":
        c_hits = matches.get("cipher_matches", [])
        e_hits = matches.get("extension_matches", [])
        lines.append(f"[~] Partial: {len(c_hits)} cipher-hash neighbors, "
                     f"{len(e_hits)} extension-hash neighbors")
        if c_hits:
            lines.append(f"   Cipher hash seen in:    {_top_apps(c_hits)}")
        if e_hits:
            lines.append(f"   Extension hash seen in: {_top_apps(e_hits)}")
    else:
        lines.append("[X] Not found in JA4DB")
        lines.append("   Could be: custom client, new malware, recent software, IoT device, or proprietary tool.")
        lines.append("   Pivot on User-Agent / src IP / dest, check threat intel, or run --vt with a VT Intelligence key.")
    return "\n".join(lines)


def format_vt(vt_result):
    if not vt_result:
        return ""
    status = vt_result.get("status")
    lines = ["\n--- VirusTotal ---", f"Query: {vt_result.get('query', '')}"]
    if status == "not_configured":
        lines.append("[!] " + vt_result.get("message", "VT not configured"))
        return "\n".join(lines)
    if status == "error":
        lines.append("[!] " + vt_result.get("message", "error"))
        return "\n".join(lines)
    if status == "not_found":
        lines.append("[X] " + vt_result.get("message", "no files"))
        return "\n".join(lines)
    lines.append(f"[OK] {vt_result.get('count', 0)} file(s) communicate with this JA4")
    for f in vt_result.get("results", []):
        lines.append("---")
        lines.append(f"   sha256     {f.get('sha256')}")
        lines.append(f"   name       {f.get('name')}")
        lines.append(f"   type       {f.get('type')}")
        lines.append(f"   verdict    malicious={f.get('malicious')} "
                     f"suspicious={f.get('suspicious')} undetected={f.get('undetected')}")
        if f.get("vt_link"):
            lines.append(f"   link       {f['vt_link']}")
        net = f.get("network")
        if isinstance(net, dict):
            for k in ("contacted_ips", "contacted_domains", "contacted_urls"):
                vals = net.get(k)
                if isinstance(vals, list) and vals:
                    lines.append(f"   {k:<13} {', '.join(str(v) for v in vals[:5])}")
    pivots = vt_result.get("network_pivots") or {}
    if any(pivots.values()):
        lines.append("---")
        lines.append("Top network pivots across enriched files:")
        for k, items in pivots.items():
            if items:
                lines.append(f"   {k}: " + ", ".join(f"{name} ({c})" for name, c in items[:5]))
    return "\n".join(lines)


# ----- CLI -----
def main():
    p = argparse.ArgumentParser(
        description="JA4 Fingerprint Lookup Tool (JA4DB + VirusTotal Intelligence)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Wildcards (CLI and VT): e.g. t13d190900_*_97f8aa674fd9 matches\n"
            "JA4_A and JA4_C while allowing any cipher hash. *_<hash>_* and\n"
            "t13* also work. See VirusTotal blog on JA4 hunting for examples."
        ),
    )
    p.add_argument("fingerprint", nargs="?",
                   help="JA4/JA4S/JA4H fingerprint or wildcard pattern (use * to wildcard a section)")
    p.add_argument("-f", "--file", help="File with fingerprints (one per line)")
    p.add_argument("-a", "--application", help="Filter results by application name")
    p.add_argument("--verified-only", action="store_true", help="Show only verified entries")
    p.add_argument("--no-cache", action="store_true", help="Disable local DB cache (slow)")
    p.add_argument("--refresh", action="store_true", help="Force refresh of local JA4DB cache")
    p.add_argument("--parse", action="store_true",
                   help="Parse fingerprint structure with field descriptions")
    p.add_argument("--csv", action="store_true", help="Print CSV (batch mode)")
    p.add_argument("--vt", action="store_true",
                   help="Also query VirusTotal Intelligence "
                        "(needs VIRUSTOTAL_API_KEY; auto-enriches with contacted IPs/domains/URLs)")
    p.add_argument("--no-vt-enrich", action="store_true",
                   help="Skip per-file network enrichment in VT (faster, fewer API calls)")
    p.add_argument("--vt-max-enrich", type=int, default=5,
                   help="Max files to enrich with contacted IPs/domains/URLs (default: 5)")
    p.add_argument("--vt-max-files", type=int, default=10,
                   help="Max files to return from VT search (default: 10)")
    p.add_argument("--yara", action="store_true",
                   help="Print a VT YARA rule scaffold for the fingerprint")
    p.add_argument("--json", dest="as_json", action="store_true",
                   help="Print full result JSON to stdout")
    p.add_argument("-o", "--output", default=None,
                   help=f"Path to write JSON results (default: "
                        f"{DEFAULT_OUTPUT_PREFIX}_<ISO8601 timestamp>.json). "
                        "Use - to skip writing the file.")
    args = p.parse_args()

    cache_dir = None if args.no_cache else DEFAULT_CACHE_DIR
    lookup = JA4Lookup(cache_dir=cache_dir)
    if args.refresh and cache_dir:
        lookup.refresh(force=True)

    vt = VirusTotalLookup() if args.vt else None
    output = {"timestamp": datetime.now().isoformat(), "results": []}

    def run_one(fp):
        record = {"fingerprint": fp, "is_wildcard": has_wildcard(fp)}
        if not has_wildcard(fp):
            record["parsed"] = parse_ja4(fp)
        matches, mt = lookup.lookup(fp)
        record["ja4db"] = {"match_type": mt, "match_count":
                           (len(matches) if isinstance(matches, list)
                            else len(matches.get("cipher_matches", []))
                                 + len(matches.get("extension_matches", []))),
                           "matches": matches}
        print(format_lookup(fp, matches, mt,
                            app_filter=args.application,
                            verified_only=args.verified_only))
        if vt:
            print("[*] Querying VirusTotal Intelligence ...", file=sys.stderr)
            vt_res = vt.lookup_ja4(fp,
                                   enrich=not args.no_vt_enrich,
                                   max_enrich=args.vt_max_enrich,
                                   max_files=args.vt_max_files)
            record["virustotal"] = vt_res
            print(format_vt(vt_res))
        if args.yara:
            rule = yara_rule_for(fp)
            record["yara"] = rule
            print("\n--- YARA rule ---\n" + rule)
        output["results"].append(record)

    if args.file:
        with open(args.file) as f:
            fps = [line.strip() for line in f if line.strip()]
        if args.csv:
            results = lookup.batch_lookup(fps)
            print("fingerprint,match_type,application,device,os,verified,observation_count")
            for fp, (matches, mt) in results.items():
                if mt in ("exact", "near", "wildcard") and isinstance(matches, list):
                    for r in matches:
                        if args.application and (r.get("application") or "").lower() != args.application.lower():
                            continue
                        if args.verified_only and not r.get("verified"):
                            continue
                        print(f'{fp},{mt},"{r.get("application","") or ""}",'
                              f'"{r.get("device","") or ""}","{r.get("os","") or ""}",'
                              f'{r.get("verified","")},{r.get("observation_count","") or ""}')
                else:
                    print(f"{fp},{mt},,,,,")
        else:
            for fp in fps:
                run_one(fp)
    elif args.fingerprint:
        if args.parse:
            parsed = parse_ja4(args.fingerprint)
            if parsed:
                print(json.dumps(parsed, indent=2))
            else:
                print("[!] Cannot parse — fingerprint contains wildcards or is malformed",
                      file=sys.stderr)
        run_one(args.fingerprint)
    else:
        p.print_help()
        return

    if args.as_json:
        print(json.dumps(output, indent=2, default=str))

    if args.output != "-":
        out_path = Path(args.output) if args.output else Path(default_output_path())
        with open(out_path, "w", encoding="utf-8") as f:
            json.dump(output, f, indent=2, default=str)
        print(f"\n[+] JSON results written to {out_path}", file=sys.stderr)


if __name__ == "__main__":
    main()
