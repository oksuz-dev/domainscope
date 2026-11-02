# DomainScope

Passive domain OSINT tool. Python 3.9+, **no dependencies**.

## Features
- DNS records (A, AAAA, MX, NS, TXT, CNAME, SOA, CAA) via Google DoH
- Subdomain discovery via certificate transparency (crt.sh) + resolution
- RDAP registration data (creation/expiry dates, status)
- HTTP security header check and TLS issuer/expiry
- JSON or Markdown report output

## Usage
```bash
python domainscope.py example.com
python domainscope.py example.com -o report.md
python domainscope.py example.com -o report.json --no-resolve
```

## Legal
Uses only public data sources and sends no attack traffic. Use only on domains you are authorized to research.

## Ideas / Roadmap
- Wayback Machine URL history
- Email SPF/DMARC analysis
- ASN / IP geolocation enrichment
- HTML report

## License
MIT
