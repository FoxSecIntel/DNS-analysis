#!/usr/bin/env python3
from __future__ import annotations

import argparse
import ipaddress
import json
import re
import socket
from typing import Dict, List

import requests
import dns.resolver

# Representative Cloudflare IPv4 ranges (not exhaustive but high-signal)
CLOUDFLARE_IPV4_RANGES = [
    "103.21.244.0/22",
    "103.22.200.0/22",
    "103.31.4.0/22",
    "104.16.0.0/13",
    "104.24.0.0/14",
    "108.162.192.0/18",
    "131.0.72.0/22",
    "141.101.64.0/18",
    "162.158.0.0/15",
    "172.64.0.0/13",
    "173.245.48.0/20",
    "188.114.96.0/20",
    "190.93.240.0/20",
    "197.234.240.0/22",
    "198.41.128.0/17",
]
CF_NETS = [ipaddress.ip_network(c) for c in CLOUDFLARE_IPV4_RANGES]


def normalise_domain(raw: str) -> str:
    d = raw.strip().lower()
    d = re.sub(r"^https?://", "", d)
    d = d.split("/")[0]
    return d


def ns_check(domain: str) -> bool:
    try:
        answers = dns.resolver.resolve(domain, "NS", lifetime=4)
        return any("cloudflare.com" in str(ns).lower() for ns in answers)
    except Exception:
        return False


def header_check(domain: str) -> bool:
    urls = [f"https://{domain}", f"http://{domain}"]
    for url in urls:
        try:
            r = requests.get(url, timeout=6, allow_redirects=True)
            server = (r.headers.get("Server") or "").lower()
            if "cloudflare" in server or "cf-ray" in {k.lower() for k in r.headers.keys()}:
                return True
        except Exception:
            continue
    return False


def ip_check(domain: str) -> bool:
    try:
        ip_str = socket.gethostbyname(domain)
        ip_obj = ipaddress.ip_address(ip_str)
        return any(ip_obj in net for net in CF_NETS)
    except Exception:
        return False


def check_domain(domain: str) -> Dict[str, object]:
    d = normalise_domain(domain)
    evidence = {
        "dns": ns_check(d),
        "header": header_check(d),
        "ip": ip_check(d),
    }
    return {
        "domain": d,
        "cloudflare": any(evidence.values()),
        "evidence": evidence,
    }


def load_targets(args: argparse.Namespace) -> List[str]:
    targets: List[str] = []
    if args.domains:
        targets.extend(args.domains)
    if args.file:
        with open(args.file, "r", encoding="utf-8", errors="ignore") as f:
            targets.extend(line.strip() for line in f if line.strip() and not line.strip().startswith("#"))
    # dedupe preserve order
    seen = set()
    out = []
    for t in targets:
        n = normalise_domain(t)
        if n and n not in seen:
            seen.add(n)
            out.append(n)
    return out


def main() -> int:
    parser = argparse.ArgumentParser(description="Detect whether domains are behind Cloudflare")
    parser.add_argument("domains", nargs="*", help="One or more domains")
    parser.add_argument("-f", "--file", help="File containing domains (one per line)")
    parser.add_argument("--json", action="store_true", help="JSON output")
    args = parser.parse_args()

    targets = load_targets(args)
    if not targets:
        parser.print_help()
        return 0

    results = [check_domain(t) for t in targets]

    if args.json:
        print(json.dumps(results, indent=2))
        return 0

    print(f"{'DOMAIN':<35} | {'CLOUDFLARE':<10} | {'DNS':<3} {'HDR':<3} {'IP':<3}")
    print("-" * 65)
    for r in results:
        ev = r["evidence"]
        print(
            f"{r['domain']:<35} | {'YES' if r['cloudflare'] else 'NO':<10} | "
            f"{'Y' if ev['dns'] else '-'}   {'Y' if ev['header'] else '-'}   {'Y' if ev['ip'] else '-'}"
        )

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
