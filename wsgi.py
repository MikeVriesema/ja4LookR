#!/usr/bin/env python3
"""Production WSGI entrypoint for JA4LookR.

Run behind a real WSGI server instead of the Flask dev server, e.g.:

    # Linux / macOS
    gunicorn --workers 4 --bind 0.0.0.0:5009 wsgi:app

    # Windows
    waitress-serve --listen=0.0.0.0:5009 wsgi:app

The DB index is pre-warmed at import time (see app.py), so each worker serves
requests from an in-memory index without hitting the network on the hot path.
"""
from app import app

if __name__ == "__main__":
    app.run()
