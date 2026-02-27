#!/usr/bin/env python3

import argparse
import base64
import ipaddress
import json
import re
import socket
import sys
from pathlib import Path
from typing import List
from urllib.error import URLError, HTTPError
from urllib.parse import urlencode
from urllib.request import Request, urlopen

try:
    import dns.resolver  # type: ignore
except Exception:  # dnspython optional
    dns = None

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
HIDDEN_MESSAGE_B64 = "wqhWaWN0b3J5IGlzIG5vdCB3aW5uaW5nIGZvciBvdXJzZWx2ZXMsIGJ1dCBmb3Igb3RoZXJzLiAtIFRoZSBNYW5kYWxvcmlhbsKoCg=="


def normalise_domain(raw):
    d = raw.strip().lower()
    d = re.sub(r"^https?://", "", d)
    d = d.split("/")[0]
    d = d.strip(".")
    return d


def dns_query(domain, rtype):
    records = []  # type: List[str]

    # 1) dnspython path (preferred)
    if dns is not None:
        try:
            answers = dns.resolver.resolve(domain, rtype)
            records = [str(a).strip().rstrip('.') for a in answers]
            if records:
                return records
        except Exception:
            pass

    # 2) DoH fallback (no dig/nslookup dependency)
    try:
        params = urlencode({"name": domain, "type": rtype})
        req = Request(f"https://dns.google/resolve?{params}", headers={"User-Agent": "Mozilla/5.0"})
        with urlopen(req, timeout=7) as r:
            payload = json.loads(r.read().decode("utf-8", errors="ignore"))
            for ans in payload.get("Answer", []) or []:
                data = str(ans.get("data", "")).strip().rstrip('.')
                if data:
                    records.append(data)
    except Exception:
        pass

    return records


def dns_ns_check(domain):
    ns_records = dns_query(domain, "NS")
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


def cname_check(domain):
    cnames = dns_query(domain, "CNAME")
    is_cf = any("cloudflare" in c.lower() for c in cnames)
    return is_cf, cnames


def check_domain(domain):
    d = normalise_domain(domain)

    ns_match, ns_records = dns_ns_check(d)
    cname_match, cnames = cname_check(d)
    hdr_match, headers = header_check(d)
    ips = resolve_ips(d)
    ip_match = ip_cf_check(ips)

    result = {
        "domain": d,
        "cloudflare": bool(ns_match or cname_match or hdr_match or ip_match),
        "signals": {
            "dns_ns": ns_match,
            "dns_cname": cname_match,
            "headers": hdr_match,
            "ip_range": ip_match,
        },
        "ns_records": ns_records,
        "cname_records": cnames,
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
    parser.add_argument("-m", action="store_true", help="Print hidden message")
    parser.add_argument("--json", action="store_true", help="Output JSON (legacy switch)")
    parser.add_argument("--output", choices=["text", "json"], default="text", help="Output format")
    parser.add_argument("--no-color", action="store_true", help="Disable ANSI colours")
    args = parser.parse_args()

    if args.m:
        print(base64.b64decode(HIDDEN_MESSAGE_B64).decode("utf-8", errors="replace"), end="")
        return 0

    targets = load_targets(args)
    results = [check_domain(t) for t in targets]

    output_json = args.json or args.output == "json"
    if output_json:
        payload = {
            "count": len(results),
            "cloudflare_detected": sum(1 for r in results if r.get("cloudflare")),
            "results": results,
        }
        print(json.dumps(payload, indent=2))
        return 0

    green = "\033[92m" if not args.no_color else ""
    red = "\033[91m" if not args.no_color else ""
    yellow = "\033[93m" if not args.no_color else ""
    reset = "\033[0m" if not args.no_color else ""

    print(f"{'DOMAIN':<35} | {'CLOUDFLARE':<12} | SIGNALS")
    print("-" * 98)
    for r in results:
        sig = r["signals"]
        sig_parts = []
        for k in ("dns_ns", "dns_cname", "headers", "ip_range"):
            v = sig.get(k, False)
            col = green if v else red
            sig_parts.append(f"{k}={col}{str(v).lower()}{reset}")

        status = f"{green}YES{reset}" if r["cloudflare"] else f"{yellow}NO{reset}"
        print(f"{r['domain']:<35} | {status:<12} | {', '.join(sig_parts)}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
