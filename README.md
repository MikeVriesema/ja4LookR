# 🔍 JA4LookR

A secure, efficient JA4 fingerprint lookup tool with both CLI and Web interfaces. Query the JA4DB to identify TLS clients, detect anomalies, and investigate potential threats.

## Features

- 🌐 **Web Interface** - Beautiful, responsive web UI for single and batch lookups
- ⚡ **CLI Tool** - Powerful command-line interface for power users and automation
- 🔒 **Secure** - Rate limiting, input validation, and CSRF protection
- 💾 **Smart Caching** - 7-day cache to reduce API calls and improve performance
- 📊 **Batch Processing** - Lookup multiple fingerprints at once (up to 100)
- 🎯 **Detailed Results** - Application, device, OS, and verification status
- 🔌 **REST API** - Programmatic access for integration with other tools

## What is JA4?

JA4 is a network fingerprinting method that identifies TLS clients based on their handshake characteristics. It's used for:
- Identifying applications and services
- Detecting malware and C2 traffic
- Network security monitoring
- Threat hunting and incident response

Learn more: [JA4+ Network Fingerprinting](https://github.com/FoxIO-LLC/ja4)

## Installation

```bash
# Clone the repository
git clone https://github.com/yourusername/ja4LookR.git
cd ja4LookR

# Install dependencies
pip3 install -r requirements.txt
```

## Usage

### Web Interface (Recommended for most users)

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

**Web Features:**
- Single fingerprint lookup with detailed analysis
- Batch lookup (up to 100 fingerprints)
- Export results as JSON
- Filter and sort results
- Responsive design for mobile and desktop

### CLI Interface (For power users)

#### Single Lookup

```bash
python3 ja4lookr.py t13d1516h2_8daaf6152771_b0da82dd1658
```

#### Parse Fingerprint Structure

```bash
python3 ja4lookr.py --parse t13d1516h2_8daaf6152771_b0da82dd1658
```

#### Batch Lookup from File

```bash
# Create a file with fingerprints (one per line)
echo "t13d1516h2_8daaf6152771_b0da82dd1658" > fingerprints.txt
echo "t13d1517h2_5b57614c22b0_3d7a3b2f1c8e" >> fingerprints.txt

# Lookup all fingerprints
python3 ja4lookr.py -f fingerprints.txt
```

#### CSV Output

```bash
python3 ja4lookr.py -f fingerprints.txt --csv > results.csv
```

#### Filter Results

```bash
# Show only verified entries
python3 ja4lookr.py -f fingerprints.txt --verified-only

# Filter by application
python3 ja4lookr.py -f fingerprints.txt -a "Chrome"
```

#### Disable Cache

```bash
python3 ja4lookr.py --no-cache t13d1516h2_8daaf6152771_b0da82dd1658
```

### REST API

The web server provides a REST API for programmatic access:

```bash
# Lookup a fingerprint
curl http://localhost:5000/api/lookup/t13d1516h2_8daaf6152771_b0da82dd1658

# Health check
curl http://localhost:5000/health
```

**Response Format:**

```json
{
  "fingerprint": "t13d1516h2_8daaf6152771_b0da82dd1658",
  "result": [...],
  "parsed": {
    "protocol": "t13",
    "is_tls13": true,
    "cipher_hash": "8daaf6152771",
    "extension_hash": "b0da82dd1658"
  },
  "timestamp": "2024-01-08T12:34:56"
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

## Performance Optimizations

- **Intelligent Caching**: Results cached for 7 days (including 404s)
- **Session Reuse**: HTTP connection pooling for API calls
- **Lazy Loading**: Templates loaded on-demand
- **Minimal Dependencies**: Only essential packages included

## Configuration

### Environment Variables

```bash
# Flask secret key (change in production!)
export SECRET_KEY="your-secure-random-key-here"

# Cache directory (default: .ja4_cache)
export CACHE_DIR="/path/to/cache"

# Cache duration in days (default: 7)
export CACHE_DAYS="7"
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
# You captured a JA4 fingerprint from network traffic
python3 ja4lookr.py t13d1516h2_8daaf6152771_b0da82dd1658

# Result shows it's Chrome on Windows - legitimate traffic
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
    if echo "$result" | grep -q "not_found"; then
        echo "ALERT: Unknown fingerprint detected: $fingerprint"
        # Send alert to your monitoring system
    fi
done < new_fingerprints.txt
```

## CLI Options Reference

```
usage: ja4lookr.py [-h] [-f FILE] [-a APPLICATION] [--verified-only]
                   [--no-cache] [--parse] [--csv] [fingerprint]

JA4 Fingerprint Lookup Tool

positional arguments:
  fingerprint           JA4/JA4H/JA4S fingerprint to lookup

optional arguments:
  -h, --help            show this help message and exit
  -f FILE, --file FILE  File with fingerprints (one per line)
  -a APPLICATION, --application APPLICATION
                        Filter by application name
  --verified-only       Show only verified entries
  --no-cache            Disable cache
  --parse               Parse fingerprint structure
  --csv                 Output in CSV format
```

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
# Clear the cache
rm -rf .ja4_cache/

# Or disable cache temporarily
python3 ja4lookr.py --no-cache <fingerprint>
```

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
