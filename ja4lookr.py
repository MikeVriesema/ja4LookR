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


# FoxIO moved JA4DB behind ja4db.foxio.io; the endpoint (and whether it needs an
# account/API key) can change. Override with the JA4DB_URL env var if needed.
JA4DB_URL = os.getenv("JA4DB_URL", "https://ja4db.com/api/read/")
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


# ----- JA4+ suite: type detection + structural decoding -----
# The full suite: JA4 (TLS client), JA4S (TLS server), JA4H (HTTP client),
# JA4X (X.509 cert), JA4T/JA4TS/JA4TScan (TCP). Each has its own layout; the
# JA4DB indexes them all, so exact/wildcard lookup works for every type — these
# decoders add the human-readable "signature breakdown" per type.

HTTP_METHODS = {"ge": "GET", "po": "POST", "pu": "PUT", "de": "DELETE",
                "he": "HEAD", "op": "OPTIONS", "pa": "PATCH", "co": "CONNECT",
                "tr": "TRACE"}
HTTP_VERSIONS = {"10": "HTTP/1.0", "11": "HTTP/1.1", "20": "HTTP/2", "30": "HTTP/3"}


JA4H_A_RE = re.compile(r"^[a-z]{2}\d{2}[cn][rn]\d{2}")  # method,ver,cookie,referer,hdrs
JA4SSH_SEG_RE = re.compile(r"^c\d+s\d+$")               # cNNsNN
DASH_NUM_RE = re.compile(r"^\d+(?:-\d+)*$")             # dash-separated integer list
# DHCPv6 message-type tokens (ja4d6 first segment starts with one of these).
JA4D6_TYPES = ("solct", "solic", "adver", "confi", "renew", "rebin",
               "reply", "recon", "relea", "decli", "infor")


def detect_ja4_type(fp):
    """Best-effort classification of a JA4+ fingerprint into its suite member."""
    if not fp or "*" in fp:
        return "unknown"
    s = fp.strip().lower()
    parts = s.split("_")
    np = len(parts)

    # JA4SSH: every segment is cNNsNN (client/server payload, packet, ack counts).
    if 2 <= np <= 3 and all(JA4SSH_SEG_RE.match(p) for p in parts):
        return "ja4ssh"
    # TCP numeric family: window_options_mss_scale[_scanresponses].
    if np in (4, 5) and all(re.fullmatch(r"[\d\-]+", p) for p in parts):
        return "ja4tscan" if np == 5 else "ja4t"
    # JA4L / JA4LS: 2–3 plain integers (latency[_ttl][_app-handshake-latency]).
    # Exclude the all-12-digit case, which is a JA4X hash triple.
    if np in (2, 3) and all(p.isdigit() for p in parts) \
            and not (np == 3 and all(len(p) == 12 for p in parts)):
        return "ja4l"
    # JA4D / JA4D6 (DHCP): message-type word + two dash-number option lists.
    if np == 3 and re.match(r"^[a-z]{3,}", parts[0]) and \
            DASH_NUM_RE.match(parts[1]) and DASH_NUM_RE.match(parts[2]):
        return "ja4d6" if parts[0][:5] in JA4D6_TYPES else "ja4d"
    # JA4H (HTTP): ja4h_a pattern, emitted with 2, 3, or 4 sections.
    if 2 <= np <= 4 and JA4H_A_RE.match(parts[0]):
        return "ja4h"
    if np == 3:
        a, b, c = parts
        # JA4X: three 12-hex hashes, no structured ja4_a.
        if all(re.fullmatch(r"[0-9a-f]{12}", p) for p in parts):
            return "ja4x"
        # JA4 (client): ja4_a is 10 chars with a d/i SNI flag at index 3.
        if re.match(r"^[a-z]\d\d[di]\d{4}[a-z0-9]{2}$", a) and \
           re.fullmatch(r"[0-9a-f]{12}", b) and re.fullmatch(r"[0-9a-f]{12}", c):
            return "ja4"
        # JA4S (server): ja4_a is 7 chars, ja4_b is a 4-hex chosen cipher.
        if re.match(r"^[a-z]\d\d\d{2}[a-z0-9]{2}$", a) and re.fullmatch(r"[0-9a-f]{4}", b):
            return "ja4s"
    return "unknown"


def _seg(label, chars):
    return {"label": label, "chars": chars}


def _field(code, label, meaning, sev=None):
    return {"code": code, "label": label, "meaning": meaning, "sev": sev}


def parse_ja4s(fp):
    """Decode a JA4S (TLS server response) fingerprint.

    ja4s_a = [transport][tls_version 2c][ext_count 2d][alpn 2c]
    ja4s_b = chosen cipher suite (4 hex)
    ja4s_c = truncated SHA-256 of the server extensions
    """
    parts = fp.split("_")
    if len(parts) != 3 or len(parts[0]) < 7:
        return None
    a, b, c = parts
    transport, tls_ver, ext_code, alpn = a[0], a[1:3], a[3:5], a[5:7]
    try:
        ext_n = int(ext_code)
    except ValueError:
        ext_n = None
    fields = [
        _field(transport, "Transport", TRANSPORT.get(transport, f"Unknown ({transport})")),
        _field(tls_ver, "TLS version", TLS_VERSIONS.get(tls_ver, f"Unknown ({tls_ver})"),
               sev="high" if tls_ver in LEGACY_TLS else None),
        _field(ext_code, "Extensions", f"{ext_n} server extensions" if ext_n is not None else "unparsed"),
        _field(alpn, "ALPN", ALPN_KNOWN.get(alpn, f"ALPN '{alpn}'"),
               sev="low" if alpn == "00" else None),
        _field(b, "Chosen cipher", f"Server-selected cipher suite 0x{b}"),
        _field(c, "Extension hash", "SHA-256 of the server extensions (truncated)"),
    ]
    segments = [
        _seg("JA4S_a", [{"v": transport}, {"v": tls_ver}, {"v": ext_code}, {"v": alpn}]),
        _seg("JA4S_b", [{"v": b}]),
        _seg("JA4S_c", [{"v": c}]),
    ]
    summary = (f"{TRANSPORT.get(transport, transport)} server · "
               f"{TLS_VERSIONS.get(tls_ver, tls_ver)} · {ext_n} extensions · "
               f"cipher 0x{b} · ALPN={ALPN_KNOWN.get(alpn, alpn)}")
    return {"fields": fields, "segments": segments, "summary": summary}


def parse_ja4h(fp):
    """Decode a JA4H (HTTP client) fingerprint.

    ja4h_a = [method 2c][version 2d][cookie c/n][referer r/n][hdr_count 2d][accept_lang 4c]
    ja4h_b = truncated hash of the header names
    ja4h_c = truncated hash of the Cookie field names
    ja4h_d = truncated hash of the Cookie name=value pairs (omitted in the 3-part form)
    """
    parts = fp.split("_")
    if len(parts) not in (2, 3, 4) or len(parts[0]) < 12:
        return None
    a, b = parts[0], parts[1]
    c = parts[2] if len(parts) >= 3 else None
    d = parts[3] if len(parts) == 4 else None
    method, ver, cookie, referer, hdr_code, lang = a[:2], a[2:4], a[4], a[5], a[6:8], a[8:12]
    try:
        hdr_n = int(hdr_code)
    except ValueError:
        hdr_n = None
    lang_h = "none" if lang == "0000" else lang.replace("0", "").upper() or lang
    fields = [
        _field(method, "Method", HTTP_METHODS.get(method, f"Unknown ({method})")),
        _field(ver, "HTTP version", HTTP_VERSIONS.get(ver, f"Unknown ({ver})")),
        _field(cookie, "Cookie", "Cookie header present" if cookie == "c" else "no Cookie header"),
        _field(referer, "Referer", "Referer present" if referer == "r" else "no Referer"),
        _field(hdr_code, "Headers", f"{hdr_n} headers" if hdr_n is not None else "unparsed"),
        _field(lang, "Accept-Language", f"primary language {lang_h}"),
        _field(b, "Header hash", "SHA-256 of the ordered header names (truncated)"),
    ]
    a_chars = [{"v": method}, {"v": ver}, {"v": cookie}, {"v": referer},
               {"v": hdr_code}, {"v": lang}]
    segments = [_seg("JA4H_a", a_chars), _seg("JA4H_b", [{"v": b}])]
    if c is not None:
        fields.append(_field(c, "Cookie-field hash", "SHA-256 of the Cookie field names (truncated)"))
        segments.append(_seg("JA4H_c", [{"v": c}]))
    if d is not None:
        fields.append(_field(d, "Cookie-value hash", "SHA-256 of the Cookie name=value pairs (truncated)"))
        segments.append(_seg("JA4H_d", [{"v": d}]))
    summary = (f"{HTTP_METHODS.get(method, method)} · {HTTP_VERSIONS.get(ver, ver)} · "
               f"{'cookie' if cookie == 'c' else 'no cookie'} · "
               f"{'referer' if referer == 'r' else 'no referer'} · {hdr_n} headers")
    return {"fields": fields, "segments": segments, "summary": summary}


def parse_ja4t(fp):
    """Decode a JA4T (TCP) fingerprint: window_options_mss_windowscale."""
    parts = fp.split("_")
    if len(parts) != 4:
        return None
    window, opts, mss, scale = parts
    fields = [
        _field(window, "TCP window", f"advertised window size {window}"),
        _field(opts, "TCP options", f"option kinds in order: {opts or 'none'}"),
        _field(mss, "MSS", f"maximum segment size {mss}"),
        _field(scale, "Window scale", f"window scale {scale}"),
    ]
    segments = [_seg("WINDOW", [{"v": window}]), _seg("OPTIONS", [{"v": opts or "-"}]),
                _seg("MSS", [{"v": mss}]), _seg("SCALE", [{"v": scale}])]
    summary = f"TCP · window {window} · MSS {mss} · scale {scale} · opts {opts or 'none'}"
    return {"fields": fields, "segments": segments, "summary": summary}


def parse_ja4tscan(fp):
    """Decode a JA4TScan (active TCP scan) fingerprint.

    window_options_mss_windowscale_<responses> — JA4T fields plus the ordered
    RST/retransmit response pattern observed during an active scan.
    """
    parts = fp.split("_")
    if len(parts) != 5:
        return None
    window, opts, mss, scale, resp = parts
    fields = [
        _field(window, "TCP window", f"advertised window size {window}"),
        _field(opts, "TCP options", f"option kinds in order: {opts or 'none'}"),
        _field(mss, "MSS", f"maximum segment size {mss}"),
        _field(scale, "Window scale", f"window scale {scale}"),
        _field(resp, "Scan responses", f"observed retransmit / RST pattern: {resp}"),
    ]
    segments = [_seg("WINDOW", [{"v": window}]), _seg("OPTIONS", [{"v": opts or "-"}]),
                _seg("MSS", [{"v": mss}]), _seg("SCALE", [{"v": scale}]),
                _seg("RESPONSES", [{"v": resp}])]
    summary = f"active TCP scan · window {window} · MSS {mss} · scale {scale} · responses {resp}"
    return {"fields": fields, "segments": segments, "summary": summary}


def parse_ja4ssh(fp):
    """Decode a JA4SSH (SSH traffic) fingerprint: cNNsNN_cNNsNN_cNNsNN.

    Sampled over a window of SSH packets. The three segments carry, in order,
    the mode client/server payload sizes, packet counts, and TCP ACK counts.
    """
    parts = fp.split("_")
    if not (2 <= len(parts) <= 3) or not all(JA4SSH_SEG_RE.match(p) for p in parts):
        return None
    labels = ["Payload sizes", "Packet counts", "ACK counts"]
    meanings = ["mode client/server SSH payload length",
                "client/server packet counts in the window",
                "client/server TCP ACK counts in the window"]
    fields, segments = [], []
    for i, p in enumerate(parts):
        cval, sval = p[1:].split("s")
        fields.append(_field(p, labels[i], f"{meanings[i]} — client {cval}, server {sval}"))
        segments.append(_seg(labels[i].upper(), [{"v": p}]))
    summary = "SSH session · " + " · ".join(f"{labels[i].lower()} {parts[i]}"
                                            for i in range(len(parts)))
    return {"fields": fields, "segments": segments, "summary": summary}


def parse_ja4l(fp):
    """Decode a JA4L / JA4LS (latency / light-distance) fingerprint.

    latency_ttl[_apphandshake] — one-way TCP latency (µs), observed IP TTL, and
    (optionally) one-way application-handshake latency. TTL vs the known initial
    TTL yields the hop count; latency yields light-distance to the peer.
    """
    parts = fp.split("_")
    if len(parts) not in (2, 3) or not all(p.isdigit() for p in parts):
        return None
    latency, ttl = parts[0], parts[1]
    app = parts[2] if len(parts) == 3 else None
    fields = [
        _field(latency, "TCP latency", f"one-way TCP latency ~{latency} µs (1 ms = 1000 µs)"),
        _field(ttl, "Observed TTL", f"IP TTL {ttl} — vs the initial TTL gives hop count / distance"),
    ]
    segments = [_seg("LATENCY", [{"v": latency}]), _seg("TTL", [{"v": ttl}])]
    if app is not None:
        fields.append(_field(app, "App latency", f"one-way application-handshake latency ~{app} µs"))
        segments.append(_seg("APP-LATENCY", [{"v": app}]))
    summary = (f"latency ~{latency} µs · TTL {ttl}" + (f" · app ~{app} µs" if app else ""))
    return {"fields": fields, "segments": segments, "summary": summary}


def _parse_dhcp(fp, v6):
    """Shared decoder for JA4D (DHCP) / JA4D6 (DHCPv6): msgtype_options_params."""
    parts = fp.split("_")
    if len(parts) != 3:
        return None
    a, opts, params = parts
    proto = "DHCPv6" if v6 else "DHCP"
    fields = [
        _field(a, "Message type", f"{proto} message-type block (e.g. discover/solicit) + flags"),
        _field(opts, "Options present", f"ordered {proto} option codes: {opts}"),
        _field(params, "Requested params", f"parameter / option request list: {params}"),
    ]
    segments = [_seg("MSGTYPE", [{"v": a}]), _seg("OPTIONS", [{"v": opts}]),
                _seg("PARAMS", [{"v": params}])]
    return {"fields": fields, "segments": segments,
            "summary": f"{proto} fingerprint · {a} · {opts.count('-') + 1} options"}


def parse_ja4d(fp):
    return _parse_dhcp(fp, v6=False)


def parse_ja4d6(fp):
    return _parse_dhcp(fp, v6=True)


def parse_ja4x(fp):
    """Decode a JA4X (X.509 certificate) fingerprint: issuer_subject_extensions."""
    parts = fp.split("_")
    if len(parts) != 3:
        return None
    issuer, subject, exts = parts
    fields = [
        _field(issuer, "Issuer RDNs", "SHA-256 of the issuer RDN set (truncated)"),
        _field(subject, "Subject RDNs", "SHA-256 of the subject RDN set (truncated)"),
        _field(exts, "Cert extensions", "SHA-256 of the certificate extensions (truncated)"),
    ]
    segments = [_seg("ISSUER", [{"v": issuer}]), _seg("SUBJECT", [{"v": subject}]),
                _seg("EXTENSIONS", [{"v": exts}])]
    return {"fields": fields, "segments": segments,
            "summary": "X.509 certificate fingerprint · issuer / subject / extensions hashes"}


TYPE_LABELS = {
    "ja4": "JA4 · TLS Client", "ja4s": "JA4S · TLS Server",
    "ja4h": "JA4H · HTTP Client", "ja4x": "JA4X · X.509 Certificate",
    "ja4t": "JA4T · TCP Client", "ja4ts": "JA4TS · TCP Server",
    "ja4tscan": "JA4TScan · Active TCP Scan", "ja4ssh": "JA4SSH · SSH Traffic",
    "ja4l": "JA4L · Latency / Light-Distance", "ja4ls": "JA4LS · Server Latency",
    "ja4d": "JA4D · DHCP", "ja4d6": "JA4D6 · DHCPv6",
    "unknown": "Unrecognised fingerprint",
}


def signature_breakdown(fp):
    """Normalised, template-friendly decode of any JA4+ suite fingerprint.

    Returns {type, type_label, fingerprint, valid, segments, decode, summary,
    risk} — a uniform shape the CLI and web UI render for every suite member.
    Wildcards and unrecognised inputs return valid=False.
    """
    if not fp or "*" in fp:
        return {"type": "unknown", "type_label": TYPE_LABELS["unknown"],
                "fingerprint": fp, "valid": False,
                "segments": [], "decode": [], "summary": "", "risk": None}
    fp = fp.strip()
    t = detect_ja4_type(fp)
    risk = None

    if t == "ja4":
        p = parse_ja4(fp)
        if not p:
            t = "unknown"
        else:
            risk = p["risk"]
            flags = {f["code"]: f["severity"] for f in risk["flags"]}
            comp = p["components"]
            decode = [
                _field(comp["transport"]["code"], "Protocol", comp["transport"]["meaning"],
                       flags.get("quic")),
                _field(comp["tls_version"]["code"], "TLS version", comp["tls_version"]["meaning"],
                       flags.get("legacy_tls")),
                _field(comp["sni"]["code"], "SNI", comp["sni"]["meaning"], flags.get("no_sni_ip")),
                _field(comp["cipher_count"]["code"], "Cipher suites", comp["cipher_count"]["meaning"]),
                _field(comp["extension_count"]["code"], "Extensions", comp["extension_count"]["meaning"]),
                _field(comp["alpn"]["code"], "ALPN", comp["alpn"]["meaning"], flags.get("no_alpn")),
                _field(p["ja4_b_cipher_hash"], "Cipher hash", "SHA-256 of the sorted cipher suites (truncated)"),
                _field(p["ja4_c_extension_hash"], "Extension hash",
                       "SHA-256 of sorted extensions + signature algorithms (truncated)"),
            ]
            a = comp
            segments = [
                _seg("JA4_a", [
                    {"v": a["transport"]["code"], "sev": flags.get("quic")},
                    {"v": a["tls_version"]["code"], "sev": flags.get("legacy_tls")},
                    {"v": a["sni"]["code"], "sev": flags.get("no_sni_ip")},
                    {"v": a["cipher_count"]["code"]},
                    {"v": a["extension_count"]["code"]},
                    {"v": a["alpn"]["code"], "sev": flags.get("no_alpn")},
                ]),
                _seg("JA4_b", [{"v": p["ja4_b_cipher_hash"]}]),
                _seg("JA4_c", [{"v": p["ja4_c_extension_hash"]}]),
            ]
            return {"type": "ja4", "type_label": TYPE_LABELS["ja4"], "fingerprint": fp,
                    "valid": True, "segments": segments, "decode": decode,
                    "summary": p["summary"], "risk": risk}

    parser = {"ja4s": parse_ja4s, "ja4h": parse_ja4h, "ja4t": parse_ja4t,
              "ja4ts": parse_ja4t, "ja4tscan": parse_ja4tscan, "ja4ssh": parse_ja4ssh,
              "ja4l": parse_ja4l, "ja4ls": parse_ja4l, "ja4d": parse_ja4d,
              "ja4d6": parse_ja4d6, "ja4x": parse_ja4x}.get(t)
    if parser:
        d = parser(fp)
        if d:
            return {"type": t, "type_label": TYPE_LABELS[t], "fingerprint": fp,
                    "valid": True, "segments": d["segments"], "decode": d["fields"],
                    "summary": d["summary"], "risk": None}

    return {"type": "unknown", "type_label": TYPE_LABELS["unknown"], "fingerprint": fp,
            "valid": False, "segments": [], "decode": [], "summary": "", "risk": None}


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
        headers = {}
        api_key = os.getenv("JA4DB_API_KEY")
        if api_key:
            headers["Authorization"] = f"Bearer {api_key}"
        try:
            resp = requests.get(JA4DB_URL, timeout=60, headers=headers)
            resp.raise_for_status()
            data = resp.json()
        except (requests.exceptions.RequestException, ValueError) as e:
            # Fall back to a stale cache if we have one, so the tool stays usable.
            if path and path.exists():
                print(f"[!] JA4DB pull failed ({e}); using existing cached copy.",
                      file=sys.stderr)
                with gzip.open(path, "rt", encoding="utf-8") as f:
                    self._db = json.load(f)
                self._indexes = None
                return
            raise RuntimeError(
                f"Could not download JA4DB from {JA4DB_URL}: {e}\n"
                "FoxIO moved JA4DB to ja4db.foxio.io and the anonymous endpoint "
                "may now require an account/API key. Set the JA4DB_URL env var to "
                "the current endpoint (and JA4DB_API_KEY if it needs a token), "
                "or place a JSON copy at .ja4_cache/ja4db_full.json.gz."
            ) from e
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
        if path and path.exists():
            # Offline-first: always serve the bundled/cached DB without blocking
            # on the network. The live JA4DB moved behind ja4db.foxio.io
            # (enterprise access), so freshness only drives an explicit
            # --refresh — never a lazy fetch on the request hot path.
            with gzip.open(path, "rt", encoding="utf-8") as f:
                self._db = json.load(f)
            self._indexes = None
            return
        # No local cache at all: attempt a one-time pull (may raise if offline).
        self.refresh(force=True)

    def warm(self):
        """Eagerly load the DB and build indexes (used to pre-warm the web app)."""
        self._load()
        self._build_indexes()

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

    # VT's behaviour_network search indexes the TLS JA4/JA4S seen during
    # detonation. HTTP/cert/TCP suite members aren't queryable this way.
    VT_SUPPORTED_TYPES = ("ja4", "ja4s")

    def lookup_ja4(self, ja4_or_pattern, enrich=True, max_enrich=5,
                   max_files=10, network_limit=10):
        if not self.is_configured():
            return {"status": "not_configured",
                    "message": "Set VIRUSTOTAL_API_KEY (or VT_API_KEY) to enable VT lookup"}
        # Type-gate: wildcards are allowed (JA4 hunting); typed inputs must be a
        # TLS member VT can actually search on.
        if "*" not in ja4_or_pattern:
            ftype = detect_ja4_type(ja4_or_pattern)
            if ftype not in self.VT_SUPPORTED_TYPES:
                return {"status": "unsupported_type",
                        "query": f"behavior_network:{ja4_or_pattern}",
                        "message": f"VirusTotal behaviour search covers JA4/JA4S "
                                   f"(TLS); {TYPE_LABELS.get(ftype, ftype)} fingerprints "
                                   f"aren't indexed there. JA4DB results still apply."}
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

    if args.vt_check:
        status = VirusTotalLookup().verify_key()
        print(f"VirusTotal key: {status['status']} — {status['message']}")
        return

    def _write_json(out):
        if args.as_json:
            print(json.dumps(out, indent=2, default=str))
        if args.output != "-":
            out_path = Path(args.output) if args.output else Path(default_output_path())
            with open(out_path, "w", encoding="utf-8") as f:
                json.dump(out, f, indent=2, default=str)
            print(f"\n[+] JSON results written to {out_path}", file=sys.stderr)

    if args.hunt:
        criteria = [c for c in args.hunt.split(",") if c.strip()]
        records = lookup.hunt(criteria, app_filter=args.application,
                              verified_only=args.verified_only)
        print(format_hunt(set(criteria), records))
        _write_json({"timestamp": datetime.now().isoformat(), "mode": "hunt",
                     "criteria": criteria, "count": len(records),
                     "records": records})
        return

    if args.search:
        records = lookup.search_metadata(args.search, field=args.field)
        print(format_search(args.search, args.field, records))
        _write_json({"timestamp": datetime.now().isoformat(), "mode": "search",
                     "term": args.search, "field": args.field,
                     "count": len(records), "records": records})
        return

    vt = VirusTotalLookup() if args.vt else None
    output = {"timestamp": datetime.now().isoformat(), "results": []}

    def run_one(fp):
        record = {"fingerprint": fp, "is_wildcard": has_wildcard(fp)}
        if not has_wildcard(fp):
            record["parsed"] = parse_ja4(fp)
            sig = signature_breakdown(fp)
            record["signature"] = sig
            if sig["valid"] and sig["type"] != "ja4":
                print(f"\n{sig['type_label']}\n   {sig['summary']}")
                for f in sig["decode"]:
                    print(f"   {f['label']:<18} {f['code']}  —  {f['meaning']}")
        matches, mt = lookup.lookup(fp)
        record["ja4db"] = {"match_type": mt, "match_count":
                           (len(matches) if isinstance(matches, list)
                            else len(matches.get("cipher_matches", []))
                                 + len(matches.get("extension_matches", []))),
                           "matches": matches}
        print(format_lookup(fp, matches, mt,
                            app_filter=args.application,
                            verified_only=args.verified_only))
        if record.get("parsed") and record["parsed"].get("risk"):
            print(format_risk(record["parsed"]["risk"]))
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
            sig = signature_breakdown(args.fingerprint)
            if sig["valid"]:
                print(json.dumps(sig, indent=2))
            else:
                print("[!] Cannot parse — fingerprint contains wildcards or is "
                      "an unrecognised JA4+ format", file=sys.stderr)
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
    try:
        main()
    except RuntimeError as e:
        print(f"[!] {e}", file=sys.stderr)
        sys.exit(1)
