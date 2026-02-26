#!/usr/bin/env python3

import argparse
import ipaddress
import json
import re
import socket
import subprocess
import sys
from pathlib import Path
from typing import Dict, List, Tuple
from urllib.error import URLError, HTTPError
from urllib.request import Request, urlopen

# Representative Cloudflare anycast ranges (not exhaustive, but high-signal)
CF_CIDRS = [
    "103.21.244.0/22", "103.22.200.0/22", "103.31.4.0/22", "104.16.0.0/13",
    "104.24.0.0/14", "108.162.192.0/18", "131.0.72.0/22", "141.101.64.0/18",
    "162.158.0.0/15", "172.64.0.0/13", "173.245.48.0/20", "188.114.96.0/20",
    "190.93.240.0/20", "197.234.240.0/22", "198.41.128.0/17",
    "2400:cb00::/32", "2405:8100::/32", "2405:b500::/32", "2606:4700::/32",
    "2803:f800::/32", "2a06:98c0::/29", "2c0f:f248::/32",
]
CF_NETS = [ipaddress.ip_network(c) for c in CF_CIDRS]


def normalise_domain(raw):
    d = raw.strip().lower()
    d = re.sub(r"^https?://", "", d)
    d = d.split("/")[0]
    d = d.strip(".")
    return d


def dns_ns_check(domain):
    ns_records = []  # type: List[str]

    # Prefer dig if available
    if subprocess.call(["bash", "-lc", "command -v dig >/dev/null 2>&1"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL) == 0:
        try:
            out = subprocess.check_output(["dig", "+short", "NS", domain], text=True, timeout=6)
            ns_records = [x.strip().rstrip(".") for x in out.splitlines() if x.strip()]
        except Exception:
            ns_records = []
    else:
        # Fallback nslookup
        try:
            out = subprocess.check_output(["nslookup", "-type=ns", domain], text=True, timeout=6)
            for line in out.splitlines():
                if "nameserver" in line.lower() and "=" in line:
                    ns_records.append(line.split("=", 1)[1].strip().rstrip("."))
        except Exception:
            ns_records = []

    is_cf = any("cloudflare" in ns.lower() for ns in ns_records)
    return is_cf, ns_records


def header_check(domain):
    headers_out = {}
    for scheme in ("https", "http"):
        url = f"{scheme}://{domain}"
        try:
            req = Request(url, headers={"User-Agent": "Mozilla/5.0"})
            with urlopen(req, timeout=7) as r:
                headers = {k.lower(): v for k, v in r.headers.items()}
                headers_out = headers
                if "cf-ray" in headers or "cf-cache-status" in headers:
                    return True, headers
                if "cloudflare" in headers.get("server", "").lower():
                    return True, headers
        except (HTTPError, URLError, TimeoutError, ValueError):
            continue
        except Exception:
            continue
    return False, headers_out


def resolve_ips(domain):
    ips = set()
    try:
        infos = socket.getaddrinfo(domain, None)
        for i in infos:
            ip = i[4][0]
            ips.add(ip)
    except Exception:
        pass
    return sorted(ips)


def ip_cf_check(ips):
    for ip in ips:
        try:
            addr = ipaddress.ip_address(ip)
            for net in CF_NETS:
                if addr.version == net.version and addr in net:
                    return True
        except ValueError:
            continue
    return False


def check_domain(domain):
    d = normalise_domain(domain)

    ns_match, ns_records = dns_ns_check(d)
    hdr_match, headers = header_check(d)
    ips = resolve_ips(d)
    ip_match = ip_cf_check(ips)

    result = {
        "domain": d,
        "cloudflare": bool(ns_match or hdr_match or ip_match),
        "signals": {
            "dns_ns": ns_match,
            "headers": hdr_match,
            "ip_range": ip_match,
        },
        "ns_records": ns_records,
        "resolved_ips": ips,
        "header_server": headers.get("server") if headers else None,
    }
    return result


def load_targets(args):
    targets = list(args.domains or [])
    if args.file:
        p = Path(args.file)
        if not p.exists():
            print(f"Error: file not found: {p}", file=sys.stderr)
            sys.exit(1)
        targets.extend([l.strip() for l in p.read_text(encoding="utf-8", errors="ignore").splitlines() if l.strip() and not l.strip().startswith("#")])
    if not targets:
        print("No domains supplied. Use positional args or --file.", file=sys.stderr)
        sys.exit(1)
    return targets


def main() -> int:
    parser = argparse.ArgumentParser(description="Check whether domains are behind Cloudflare")
    parser.add_argument("domains", nargs="*", help="One or more domains")
    parser.add_argument("-f", "--file", help="File with one domain per line")
    parser.add_argument("--json", action="store_true", help="Output JSON")
    args = parser.parse_args()

    targets = load_targets(args)
    results = [check_domain(t) for t in targets]

    if args.json:
        print(json.dumps(results, indent=2))
        return 0

    print(f"{'DOMAIN':<35} | {'CLOUDFLARE':<10} | SIGNALS")
    print("-" * 90)
    for r in results:
        sig = r["signals"]
        sig_txt = f"dns={sig['dns_ns']}, hdr={sig['headers']}, ip={sig['ip_range']}"
        print(f"{r['domain']:<35} | {('YES' if r['cloudflare'] else 'NO'):<10} | {sig_txt}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
