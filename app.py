#!/usr/bin/env python3
"""
JA4LookR Flask Web Application
A secure web interface for JA4 fingerprint lookups
"""
from flask import Flask, render_template, request, jsonify, flash, redirect, url_for
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from werkzeug.exceptions import HTTPException
import re
import json
from ja4lookr import (JA4Lookup, VirusTotalLookup, parse_ja4, yara_rule_for,
                      has_wildcard, is_browser_record)
from datetime import datetime
import os
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv('SECRET_KEY', 'ja4lookr-secure-key-change-in-production')

# Rate limiting to prevent abuse
limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"],
    storage_uri="memory://"
)

# Initialize JA4Lookup with caching
ja4_lookup = JA4Lookup()

# Initialize VirusTotal lookup (optional, requires API key)
vt_lookup = VirusTotalLookup()

# Allow alphanumerics, underscores, and `*` wildcards used for hunting patterns
JA4_PATTERN = re.compile(r'^[a-z0-9_*]{8,}$', re.IGNORECASE)


def validate_fingerprint(fingerprint):
    """Validate a JA4 fingerprint or wildcard hunting pattern."""
    if not fingerprint:
        return False, "Fingerprint cannot be empty"
    fingerprint = fingerprint.strip()
    if len(fingerprint) < 8 or len(fingerprint) > 200:
        return False, "Invalid fingerprint length"
    if not JA4_PATTERN.match(fingerprint):
        return False, "Invalid format. Expected alphanumerics, underscores, and optional * wildcards"
    return True, fingerprint

MATCH_TYPE_LABEL = {
    'exact': 'Exact match in JA4DB',
    'near': 'Near match (same cipher + extension hash, different ja4_a)',
    'wildcard': 'Wildcard pattern match',
    'cipher_variant': 'Cipher variant (same a+c, different cipher hash — possible randomization/mimicry)',
    'partial': 'Partial match (cipher hash or extension hash only)',
    'none': 'Not found in JA4DB',
}


def format_result(matches, match_type, fingerprint):
    """Format JA4Lookup result for the templates."""
    base = {
        'fingerprint': fingerprint,
        'match_type': match_type,
        'match_label': MATCH_TYPE_LABEL.get(match_type, match_type),
        'is_wildcard': has_wildcard(fingerprint),
    }
    if match_type in ('exact', 'near', 'wildcard', 'cipher_variant'):
        result = {**base, 'found': True, 'entries': matches, 'count': len(matches)}
        if match_type == 'cipher_variant':
            result['browser_mimicry'] = any(is_browser_record(r) for r in matches)
        return result
    if match_type == 'partial':
        return {**base, 'found': False, 'partial': True,
                'cipher_matches': matches.get('cipher_matches', []),
                'extension_matches': matches.get('extension_matches', []),
                'message': 'Cipher hash or extension hash matched, but no exact/near record exists.'}
    return {**base, 'found': False,
            'message': 'Fingerprint not found in JA4DB',
            'recommendation': 'Try a wildcard pattern, or pivot via VirusTotal / threat intel.'}

@app.route('/')
def index():
    """Home page with lookup form."""
    return render_template('index.html',
                           vt_configured=vt_lookup.is_configured())

@app.route('/lookup', methods=['POST'])
@limiter.limit("30 per minute")
def lookup():
    """Handle single fingerprint or wildcard lookup."""
    fingerprint = request.form.get('fingerprint', '').strip()
    enrich_vt = request.form.get('enrich_vt', 'on') == 'on'

    valid, result = validate_fingerprint(fingerprint)
    if not valid:
        flash(result, 'error')
        return redirect(url_for('index'))
    fingerprint = result

    try:
        matches, match_type = ja4_lookup.lookup(fingerprint)
        formatted = format_result(matches, match_type, fingerprint)
        parsed = parse_ja4(fingerprint)
        yara_rule = yara_rule_for(fingerprint)

        vt_result = None
        if vt_lookup.is_configured():
            vt_result = vt_lookup.lookup_ja4(fingerprint, enrich=enrich_vt)

        export_payload = {
            'fingerprint': fingerprint,
            'match_type': match_type,
            'is_wildcard': has_wildcard(fingerprint),
            'parsed': parsed,
            'ja4db': {'match_type': match_type, 'matches': matches},
            'virustotal': vt_result,
            'yara': yara_rule,
            'timestamp': datetime.now().isoformat(),
        }

        return render_template('result.html',
                               result=formatted,
                               parsed=parsed,
                               vt_result=vt_result,
                               vt_configured=vt_lookup.is_configured(),
                               yara_rule=yara_rule,
                               export_payload=export_payload,
                               timestamp=datetime.now().strftime('%Y-%m-%d %H:%M:%S'))
    except Exception as e:
        flash(f'Lookup error: {str(e)}', 'error')
        return redirect(url_for('index'))

@app.route('/batch', methods=['POST'])
@limiter.limit("10 per minute")
def batch_lookup():
    """Handle batch fingerprint lookups"""
    fingerprints_text = request.form.get('fingerprints', '').strip()

    if not fingerprints_text:
        flash('No fingerprints provided', 'error')
        return redirect(url_for('index'))

    # Parse fingerprints (one per line)
    lines = fingerprints_text.split('\n')
    fingerprints = [line.strip() for line in lines if line.strip()]

    # Limit batch size
    if len(fingerprints) > 100:
        flash('Batch size limited to 100 fingerprints', 'error')
        return redirect(url_for('index'))

    # Validate all fingerprints
    validated_fps = []
    errors = []

    for fp in fingerprints:
        valid, result = validate_fingerprint(fp)
        if valid:
            validated_fps.append(result)
        else:
            errors.append(f"Invalid: {fp} - {result}")

    if not validated_fps:
        flash('No valid fingerprints to lookup', 'error')
        return redirect(url_for('index'))

    # Perform batch lookup
    try:
        results = ja4_lookup.batch_lookup(validated_fps, show_progress=False)

        # Format results
        formatted_results = []
        for fp, (matches, match_type) in results.items():
            formatted_results.append({
                'fingerprint': fp,
                'data': format_result(matches, match_type, fp)
            })

        return render_template('batch_result.html',
                             results=formatted_results,
                             total=len(validated_fps),
                             errors=errors,
                             timestamp=datetime.now().strftime('%Y-%m-%d %H:%M:%S'))
    except Exception as e:
        flash(f'Batch lookup error: {str(e)}', 'error')
        return redirect(url_for('index'))

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


@app.route('/api/lookup/<path:fingerprint>')
@limiter.limit("60 per minute")
def api_lookup(fingerprint):
    """REST API endpoint with full feature parity (JA4DB + VT + YARA)."""
    valid, result = validate_fingerprint(fingerprint)
    if not valid:
        return jsonify({'error': result}), 400
    fingerprint = result

    include_vt = request.args.get('vt', '0') in ('1', 'true', 'yes')
    enrich_vt = request.args.get('enrich', '1') in ('1', 'true', 'yes')

    try:
        matches, match_type = ja4_lookup.lookup(fingerprint)
        parsed = parse_ja4(fingerprint)
        vt_result = None
        if include_vt and vt_lookup.is_configured():
            vt_result = vt_lookup.lookup_ja4(fingerprint, enrich=enrich_vt)

        return jsonify({
            'fingerprint': fingerprint,
            'is_wildcard': has_wildcard(fingerprint),
            'match_type': match_type,
            'matches': matches,
            'parsed': parsed,
            'virustotal': vt_result,
            'yara': yara_rule_for(fingerprint),
            'timestamp': datetime.now().isoformat(),
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/health')
def health():
    """Health check endpoint"""
    return jsonify({'status': 'healthy', 'service': 'ja4lookr'}), 200

@app.errorhandler(429)
def ratelimit_handler(e):
    """Handle rate limit exceeded"""
    return render_template('error.html',
                         error='Rate limit exceeded',
                         message='Too many requests. Please try again later.'), 429

@app.errorhandler(Exception)
def handle_exception(e):
    """Handle all other exceptions"""
    if isinstance(e, HTTPException):
        return e

    app.logger.error(f'Unhandled exception: {str(e)}')
    return render_template('error.html',
                         error='Internal Server Error',
                         message='An unexpected error occurred.'), 500

if __name__ == '__main__':
    # Development server - localhost only for security
    # Use production WSGI server with proper network config for production
    app.run(host='127.0.0.1', port=5009, debug=False)
