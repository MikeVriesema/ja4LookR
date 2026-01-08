#!/usr/bin/env python3
import requests
import json
import argparse
from pathlib import Path
import hashlib
from datetime import datetime, timedelta

class JA4Lookup:
    def __init__(self, cache_dir=".ja4_cache", cache_days=7):
        self.base_url = "https://ja4db.com/api/read"
        self.cache_dir = Path(cache_dir)
        self.cache_dir.mkdir(exist_ok=True)
        self.cache_duration = timedelta(days=cache_days)
        self.session = requests.Session()
        
    def _cache_path(self, fingerprint):
        fp_hash = hashlib.md5(fingerprint.encode()).hexdigest()
        return self.cache_dir / f"{fp_hash}.json"
    
    def _is_cache_valid(self, cache_file):
        if not cache_file.exists():
            return False
        mtime = datetime.fromtimestamp(cache_file.stat().st_mtime)
        return datetime.now() - mtime < self.cache_duration
    
    def lookup(self, fingerprint):
        cache_file = self._cache_path(fingerprint)
        
        # Check cache first
        if self._is_cache_valid(cache_file):
            with open(cache_file, 'r') as f:
                return json.load(f)
        
        # API lookup
        url = f"{self.base_url}/{fingerprint}" if fingerprint else self.base_url
        try:
            response = self.session.get(url, timeout=10)
            
            if response.status_code == 404:
                result = {
                    "status": "not_found",
                    "fingerprint": fingerprint,
                    "message": "Fingerprint not in JA4DB - potentially custom application or new malware",
                    "recommendation": "Consider submitting to ja4db.com if legitimate traffic"
                }
            else:
                response.raise_for_status()
                result = response.json()
            
            # Cache the result (including 404s to avoid repeated lookups)
            with open(cache_file, 'w') as f:
                json.dump(result, f)
            
            return result
            
        except requests.exceptions.RequestException as e:
            return {
                "status": "error",
                "fingerprint": fingerprint,
                "error": str(e)
            }
    
    def parse_ja4(self, fingerprint):
        """Parse JA4 fingerprint into components for analysis"""
        try:
            parts = fingerprint.split('_')
            if len(parts) != 3:
                return None
            
            proto_version = parts[0][:3]  # t13, t12, q13
            details = parts[0][3:]
            
            return {
                "fingerprint": fingerprint,
                "protocol": proto_version,
                "cipher_count": details[0:2] if len(details) >= 2 else None,
                "extension_count": details[2:4] if len(details) >= 4 else None,
                "cipher_hash": parts[1],
                "extension_hash": parts[2],
                "is_tls13": proto_version == "t13",
                "is_tls12": proto_version == "t12",
                "is_quic": proto_version.startswith("q")
            }
        except Exception:
            return None
    
    def batch_lookup(self, fingerprints, show_progress=True):
        results = {}
        total = len(fingerprints)
        
        for idx, fp in enumerate(fingerprints, 1):
            if show_progress:
                print(f"[{idx}/{total}] Looking up {fp}...", end='\r')
            results[fp] = self.lookup(fp)
        
        if show_progress:
            print()  # New line after progress
        return results

def main():
    parser = argparse.ArgumentParser(description='JA4 Fingerprint Lookup Tool')
    parser.add_argument('fingerprint', nargs='?', help='JA4/JA4H/JA4S fingerprint to lookup')
    parser.add_argument('-f', '--file', help='File with fingerprints (one per line)')
    parser.add_argument('-a', '--application', help='Filter by application name')
    parser.add_argument('--verified-only', action='store_true', help='Show only verified entries')
    parser.add_argument('--no-cache', action='store_true', help='Disable cache')
    parser.add_argument('--parse', action='store_true', help='Parse fingerprint structure')
    parser.add_argument('--csv', action='store_true', help='Output in CSV format')
    
    args = parser.parse_args()
    
    cache_dir = None if args.no_cache else ".ja4_cache"
    lookup = JA4Lookup(cache_dir=cache_dir)
    
    # Batch processing from file
    if args.file:
        with open(args.file) as f:
            fingerprints = [line.strip() for line in f if line.strip()]
        results = lookup.batch_lookup(fingerprints)
        
        if args.csv:
            print("fingerprint,status,application,device,os,verified,observation_count")
        
        for fp, data in results.items():
            if data.get('status') == 'not_found':
                if args.csv:
                    print(f"{fp},not_found,,,,,")
                else:
                    print(f"\n❌ {fp}")
                    print(f"   Status: Not in database")
                    print(f"   Action: Investigate further - could be custom app or new threat")
            elif isinstance(data, list):
                for entry in data:
                    if args.application and entry.get('application') != args.application:
                        continue
                    if args.verified_only and not entry.get('verified'):
                        continue
                    
                    if args.csv:
                        print(f"{fp},found,{entry.get('application','')},{entry.get('device','')},{entry.get('os','')},{entry.get('verified','')},{entry.get('observation_count','')}")
                    else:
                        print(f"\n✓ {fp}")
                        print(f"   App: {entry.get('application', 'Unknown')}")
                        print(f"   Device: {entry.get('device', 'N/A')}")
                        print(f"   OS: {entry.get('os', 'N/A')}")
                        print(f"   Verified: {entry.get('verified', False)}")
    
    # Single lookup
    elif args.fingerprint:
        if args.parse:
            parsed = lookup.parse_ja4(args.fingerprint)
            if parsed:
                print(json.dumps(parsed, indent=2))
        
        result = lookup.lookup(args.fingerprint)
        
        if result.get('status') == 'not_found':
            print(f"\n❌ Fingerprint not found in JA4DB")
            print(f"\nFingerprint: {args.fingerprint}")
            print(f"\nThis could indicate:")
            print(f"  • Custom or proprietary application")
            print(f"  • New malware variant")
            print(f"  • Uncommon TLS client configuration")
            print(f"  • Recently released software not yet catalogued")
            print(f"\nNext steps:")
            print(f"  1. Check your logs for associated User-Agent, source IP, destination")
            print(f"  2. Cross-reference with your threat intel feeds")
            print(f"  3. If benign, consider contributing to ja4db.com")
        else:
            print(json.dumps(result, indent=2))
    
    else:
        parser.print_help()

if __name__ == "__main__":
    main()
