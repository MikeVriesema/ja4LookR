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
from ja4lookr import JA4Lookup
from datetime import datetime

app = Flask(__name__)
app.secret_key = 'ja4lookr-secure-key-change-in-production'  # Change this in production

# Rate limiting to prevent abuse
limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"],
    storage_uri="memory://"
)

# Initialize JA4Lookup with caching
ja4_lookup = JA4Lookup()

# Validation regex for JA4 fingerprints (basic pattern)
JA4_PATTERN = re.compile(r'^[a-z0-9_]{20,}$', re.IGNORECASE)

def validate_fingerprint(fingerprint):
    """Validate JA4 fingerprint format"""
    if not fingerprint:
        return False, "Fingerprint cannot be empty"

    # Remove whitespace
    fingerprint = fingerprint.strip()

    # Length check
    if len(fingerprint) < 20 or len(fingerprint) > 200:
        return False, "Invalid fingerprint length"

    # Pattern check
    if not JA4_PATTERN.match(fingerprint):
        return False, "Invalid fingerprint format. Expected alphanumeric with underscores"

    return True, fingerprint

def format_result(result, fingerprint):
    """Format API result for display"""
    if result.get('status') == 'not_found':
        return {
            'found': False,
            'fingerprint': fingerprint,
            'message': result.get('message'),
            'recommendation': result.get('recommendation')
        }
    elif result.get('status') == 'error':
        return {
            'error': True,
            'fingerprint': fingerprint,
            'message': result.get('error')
        }
    else:
        # Process successful results
        entries = result if isinstance(result, list) else [result]
        return {
            'found': True,
            'fingerprint': fingerprint,
            'entries': entries,
            'count': len(entries)
        }

@app.route('/')
def index():
    """Home page with lookup form"""
    return render_template('index.html')

@app.route('/lookup', methods=['POST'])
@limiter.limit("30 per minute")
def lookup():
    """Handle single fingerprint lookup"""
    fingerprint = request.form.get('fingerprint', '').strip()

    # Validate input
    valid, result = validate_fingerprint(fingerprint)
    if not valid:
        flash(result, 'error')
        return redirect(url_for('index'))

    fingerprint = result

    # Perform lookup
    try:
        api_result = ja4_lookup.lookup(fingerprint)
        formatted = format_result(api_result, fingerprint)

        # Parse fingerprint structure if available
        parsed = ja4_lookup.parse_ja4(fingerprint)

        return render_template('result.html',
                             result=formatted,
                             parsed=parsed,
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
        for fp, api_result in results.items():
            formatted_results.append({
                'fingerprint': fp,
                'data': format_result(api_result, fp)
            })

        return render_template('batch_result.html',
                             results=formatted_results,
                             total=len(validated_fps),
                             errors=errors,
                             timestamp=datetime.now().strftime('%Y-%m-%d %H:%M:%S'))
    except Exception as e:
        flash(f'Batch lookup error: {str(e)}', 'error')
        return redirect(url_for('index'))

@app.route('/api/lookup/<fingerprint>')
@limiter.limit("60 per minute")
def api_lookup(fingerprint):
    """REST API endpoint for programmatic access"""
    # Validate input
    valid, result = validate_fingerprint(fingerprint)
    if not valid:
        return jsonify({'error': result}), 400

    fingerprint = result

    try:
        api_result = ja4_lookup.lookup(fingerprint)
        parsed = ja4_lookup.parse_ja4(fingerprint)

        return jsonify({
            'fingerprint': fingerprint,
            'result': api_result,
            'parsed': parsed,
            'timestamp': datetime.now().isoformat()
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
    # Development server - use production WSGI server in production
    app.run(host='0.0.0.0', port=5000, debug=False)
