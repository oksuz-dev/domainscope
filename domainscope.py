#!/usr/bin/env python3
"""DomainScope - passive domain OSINT tool (stdlib only).

Sources: Google DNS-over-HTTPS, crt.sh (certificate transparency), RDAP, HTTP headers.
Only use on domains you are authorized to research.
"""
import argparse
import json
import re
import socket
import ssl
import sys
import urllib.request
import urllib.parse
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone

UA = {"User-Agent": "DomainScope/1.0 (+passive-osint)"}
RECORD_TYPES = ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA", "CAA"]
SEC_HEADERS = [
    "strict-transport-security", "content-security-policy", "x-frame-options",
    "x-content-type-options", "referrer-policy", "permissions-policy",
]


def get_json(url, timeout=20):
    req = urllib.request.Request(url, headers=UA)
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.loads(r.read().decode("utf-8", "replace"))


def dns_records(domain):
    out = {}
    def q(t):
        try:
            d = get_json(f"https://dns.google/resolve?name={urllib.parse.quote(domain)}&type={t}")
            return t, [a["data"] for a in d.get("Answer", [])]
        except Exception as e:
            return t, [f"error: {e}"]
    with ThreadPoolExecutor(8) as ex:
        for t, v in ex.map(q, RECORD_TYPES):
            if v:
                out[t] = v
    return out


def subdomains(domain):
    data, err = None, None
    for _ in range(3):  # crt.sh is flaky, retry
        try:
            data = get_json(f"https://crt.sh/?q=%25.{urllib.parse.quote(domain)}&output=json", timeout=60)
            break
        except Exception as e:
            err = str(e)
    if data is None:
        print(f"[!] crt.sh failed: {err}", file=sys.stderr)
        return {"error": err, "subdomains": []}
    subs = set()
    for row in data:
        for n in row.get("name_value", "").splitlines():
            n = n.strip().lower().lstrip("*.")
            if n.endswith(domain):
                subs.add(n)
    return {"subdomains": sorted(subs)}


def resolve_all(subs):
    def r(s):
        try:
            return s, socket.gethostbyname(s)
        except Exception:
            return s, None
    with ThreadPoolExecutor(30) as ex:
        return dict(ex.map(r, subs))


def rdap(domain):
    try:
        d = get_json(f"https://rdap.org/domain/{urllib.parse.quote(domain)}")
    except Exception as e:
        return {"error": str(e)}
    events = {e.get("eventAction"): e.get("eventDate") for e in d.get("events", [])}
    return {
        "status": d.get("status"),
        "events": events,
        "nameservers": [n.get("ldhName") for n in d.get("nameservers", [])],
    }


def http_info(domain):
    info = {}
    # Passive recon: if local CA store can't verify, retry unverified and flag it.
    for verify in (True, False):
        ctx = ssl.create_default_context()
        if not verify:
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
        try:
            req = urllib.request.Request(f"https://{domain}", headers=UA)
            with urllib.request.urlopen(req, timeout=15, context=ctx) as r:
                h = {k.lower(): v for k, v in r.headers.items()}
                info["final_url"] = r.geturl()
                info["status"] = r.status
                info["server"] = h.get("server")
                info["missing_security_headers"] = [s for s in SEC_HEADERS if s not in h]
                info["cert_verified"] = verify
            break
        except Exception as e:
            info["error"] = str(e)
    else:
        return info
    info.pop("error", None)
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with socket.create_connection((domain, 443), timeout=10) as s:
            with ctx.wrap_socket(s, server_hostname=domain) as ss:
                der = ss.getpeercert(binary_form=True)
                info["tls_cert_der_bytes"] = len(der)
                info["tls_version"] = ss.version()
    except Exception as e:
        info["tls_error"] = str(e)
    return info


def emails_from_txt(dns):
    return sorted({m for t in dns.get("TXT", []) for m in re.findall(r"[\w.+-]+@[\w-]+\.[\w.-]+", t)})


def to_markdown(r):
    L = [f"# DomainScope report: {r['domain']}", f"_Generated {r['generated']}_", ""]
    L.append("## DNS")
    for t, v in r["dns"].items():
        L += [f"- **{t}**: " + ", ".join(f"`{x}`" for x in v)]
    L += ["", "## RDAP", "```json", json.dumps(r["rdap"], indent=2), "```", "", "## HTTP/TLS"]
    L += [f"- {k}: {v}" for k, v in r["http"].items()]
    L += ["", f"## Subdomains ({len(r['subdomains'])})"]
    L += [f"- {s} -> {ip or 'unresolved'}" for s, ip in r["subdomains"].items()]
    return "\n".join(L)


def main():
    p = argparse.ArgumentParser(description="Passive domain OSINT")
    p.add_argument("domain")
    p.add_argument("-o", "--output", help="write report (.json or .md)")
    p.add_argument("--no-resolve", action="store_true", help="skip resolving subdomains")
    a = p.parse_args()
    d = a.domain.lower().strip().removeprefix("https://").removeprefix("http://").split("/")[0]

    print(f"[*] {d}: DNS...", file=sys.stderr)
    dns = dns_records(d)
    print("[*] Certificate transparency...", file=sys.stderr)
    subs = subdomains(d).get("subdomains", [])
    resolved = {s: None for s in subs} if a.no_resolve else resolve_all(subs)
    print("[*] RDAP / HTTP / TLS...", file=sys.stderr)
    report = {
        "domain": d,
        "generated": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "dns": dns,
        "emails_in_txt": emails_from_txt(dns),
        "rdap": rdap(d),
        "http": http_info(d),
        "subdomains": resolved,
    }
    if a.output:
        with open(a.output, "w", encoding="utf-8") as f:
            f.write(to_markdown(report) if a.output.endswith(".md") else json.dumps(report, indent=2))
        print(f"[+] Saved {a.output}", file=sys.stderr)
    else:
        print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
