#!/usr/bin/env python3
"""Domain security monitor with confidence metadata.

Improvements included:
- Per-domain expected nameserver overrides
- DKIM selector-aware checks with confidence scoring
- RDAP-first expiry lookup with WHOIS fallback
- Retry/backoff for DNS and HTTP calls
- Structured JSON output with status/confidence/source per signal
"""

from __future__ import annotations

import argparse
import json
import random
import re
import socket
import subprocess
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import quote
from urllib.request import Request, urlopen

BASE_DIR = Path(__file__).resolve().parent
DEFAULT_EXPECTED_NS_FILE = BASE_DIR / "config" / "expected_ns.json"
DEFAULT_DKIM_SELECTORS_FILE = BASE_DIR / "config" / "dkim_selectors.json"
VERSION = "1.0.0"


@dataclass
class Signal:
    status: str
    confidence: str
    data_source: str
    details: dict[str, Any]


def now_utc() -> str:
    return datetime.now(timezone.utc).isoformat()


def norm_ns(value: str) -> str:
    return value.strip().rstrip(".").lower()


def run_with_retry(cmd: list[str], retries: int = 3, timeout: int = 5) -> tuple[int, str, str, str]:
    last_rc = 1
    last_out = ""
    last_err = ""
    source = "dns"

    for i in range(retries):
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
            last_rc = proc.returncode
            last_out = proc.stdout.strip()
            last_err = proc.stderr.strip()
            if last_rc == 0:
                return last_rc, last_out, last_err, source
        except Exception as exc:
            last_err = str(exc)

        if i < retries - 1:
            time.sleep((0.25 * (i + 1)) + random.random() * 0.2)

    return last_rc, last_out, last_err, source


def http_json_with_retry(url: str, retries: int = 3, timeout: int = 6) -> tuple[dict[str, Any] | None, str]:
    source = "rdap"
    last_err = ""
    for i in range(retries):
        try:
            req = Request(url, headers={"User-Agent": "dns-analysis-monitor/1.0"})
            with urlopen(req, timeout=timeout) as resp:
                payload = json.loads(resp.read().decode("utf-8", errors="ignore"))
                return payload, source
        except Exception as exc:
            last_err = str(exc)
        if i < retries - 1:
            time.sleep((0.25 * (i + 1)) + random.random() * 0.2)
    return None, f"{source}_error:{last_err[:120]}"


def dig(record_type: str, name: str, retries: int = 3) -> tuple[list[str], str]:
    rc, out, err, source = run_with_retry(["dig", "+time=2", "+tries=1", "+short", record_type, name], retries=retries, timeout=6)
    if rc != 0 or not out:
        return [], f"{source}_error:{err[:120]}" if err else source
    return [line.strip() for line in out.splitlines() if line.strip()], source


def resolve_ips(domain: str) -> tuple[list[str], str]:
    try:
        _, _, ips = socket.gethostbyname_ex(domain)
        return sorted(set(ips)), "dns"
    except Exception as exc:
        return [], f"dns_error:{str(exc)[:120]}"


def load_json(path: Path, default: dict[str, Any]) -> dict[str, Any]:
    try:
        if path.exists():
            return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        pass
    return default


def check_nameservers(domain: str, expected_cfg: dict[str, Any]) -> Signal:
    ns_records, src = dig("NS", domain)
    actual = sorted(set(norm_ns(x) for x in ns_records))

    domain_overrides = {k.lower(): [norm_ns(v) for v in vals] for k, vals in (expected_cfg.get("domain_overrides") or {}).items()}
    default_ns = [norm_ns(x) for x in (expected_cfg.get("default") or [])]
    expected = sorted(set(domain_overrides.get(domain.lower(), default_ns)))

    if not actual:
        return Signal("unknown", "low", src, {"actual": [], "expected": expected, "match": None})

    if not expected:
        return Signal("unknown", "medium", src, {"actual": actual, "expected": [], "match": None})

    match = actual == expected
    return Signal(
        "pass" if match else "fail",
        "high",
        src,
        {"actual": actual, "expected": expected, "match": match},
    )


def check_spf(domain: str) -> Signal:
    txt, src = dig("TXT", domain)
    records = [x.replace('"', "") for x in txt]
    spf = [r for r in records if "v=spf1" in r.lower()]
    if not records:
        return Signal("unknown", "low", src, {"present": None, "record": None})
    if not spf:
        return Signal("fail", "high", src, {"present": False, "record": None})
    rec = spf[0]
    if "-all" in rec.lower():
        status = "pass"
    elif "~all" in rec.lower() or "?all" in rec.lower():
        status = "warn"
    else:
        status = "warn"
    return Signal(status, "high", src, {"present": True, "record": rec})


def check_dmarc(domain: str) -> Signal:
    txt, src = dig("TXT", f"_dmarc.{domain}")
    records = [x.replace('"', "") for x in txt]
    dmarc = [r for r in records if "v=dmarc1" in r.lower()]
    if not dmarc:
        return Signal("fail", "high", src, {"present": False, "policy": "missing", "record": None})

    rec = dmarc[0]
    m = re.search(r"\bp=([a-zA-Z]+)", rec, flags=re.I)
    policy = (m.group(1).lower() if m else "invalid")

    if policy == "reject":
        status = "pass"
    elif policy == "quarantine":
        status = "warn"
    elif policy == "none":
        status = "warn"
    else:
        status = "fail"

    return Signal(status, "high", src, {"present": True, "policy": policy, "record": rec})


def check_dkim(domain: str, selectors_cfg: dict[str, Any]) -> Signal:
    base = ["selector1", "selector2", "default", "google", "k1", "k2", "dkim", "mail", "smtp", "s1", "s2"]
    extra = selectors_cfg.get(domain.lower(), []) if isinstance(selectors_cfg, dict) else []
    selectors = []
    seen = set()
    for s in [*extra, *base]:
        sl = str(s).strip().lower()
        if not sl or sl in seen:
            continue
        seen.add(sl)
        selectors.append(sl)

    hits = []
    sources = set()
    for sel in selectors:
        txt, src = dig("TXT", f"{sel}._domainkey.{domain}", retries=2)
        sources.add(src)
        joined = " ".join(txt).lower()
        if "v=dkim1" in joined or " p=" in joined or "k=rsa" in joined:
            hits.append(sel)

    if hits:
        confidence = "high" if any(s in selectors[: max(1, len(extra))] for s in hits) and extra else "medium"
        return Signal("pass", confidence, "+".join(sorted(sources)), {"selectors_checked": selectors, "selectors_found": sorted(set(hits))})

    confidence = "medium" if extra else "low"
    return Signal("fail", confidence, "+".join(sorted(sources)), {"selectors_checked": selectors, "selectors_found": []})


def parse_iso_date(date_str: str) -> datetime | None:
    try:
        d = datetime.fromisoformat(date_str.replace("Z", "+00:00"))
        if d.tzinfo is None:
            d = d.replace(tzinfo=timezone.utc)
        return d.astimezone(timezone.utc)
    except Exception:
        return None


def check_expiry(domain: str) -> Signal:
    # RDAP-first
    payload, src = http_json_with_retry(f"https://rdap.org/domain/{quote(domain)}")
    if payload:
        for ev in payload.get("events", []):
            action = str(ev.get("eventAction", "")).lower()
            if action in {"expiration", "expiry", "expiration date"}:
                dt = parse_iso_date(str(ev.get("eventDate", "")))
                if dt:
                    days = (dt - datetime.now(timezone.utc)).days
                    if days < 0:
                        status = "fail"
                    elif days <= 30:
                        status = "warn"
                    else:
                        status = "pass"
                    return Signal(status, "high", "rdap", {"days": days, "expiry_utc": dt.isoformat()})

    # WHOIS fallback
    rc, out, err, whois_src = run_with_retry(["whois", domain], retries=2, timeout=10)
    text = out or ""
    patterns = [
        r"Expiry Date:\s*(.+)",
        r"Registrar Registration Expiration Date:\s*(.+)",
        r"paid-till:\s*(.+)",
        r"expires:\s*(.+)",
    ]
    candidate = None
    for p in patterns:
        m = re.search(p, text, flags=re.I)
        if m:
            candidate = m.group(1).strip().splitlines()[0].strip()
            break

    if candidate:
        dt = parse_iso_date(candidate)
        if dt:
            days = (dt - datetime.now(timezone.utc)).days
            status = "fail" if days < 0 else ("warn" if days <= 30 else "pass")
            return Signal(status, "medium", "whois", {"days": days, "expiry_utc": dt.isoformat()})

    return Signal("unknown", "low", whois_src if rc == 0 else src, {"days": None, "expiry_utc": None})


def analyse_domain(domain: str, expected_cfg: dict[str, Any], dkim_cfg: dict[str, Any]) -> dict[str, Any]:
    ips, ip_src = resolve_ips(domain)

    return {
        "domain": domain,
        "generated_at_utc": now_utc(),
        "signals": {
            "ip_resolution": Signal("pass" if ips else "unknown", "high" if ips else "low", ip_src, {"ips": ips}).__dict__,
            "nameservers": check_nameservers(domain, expected_cfg).__dict__,
            "spf": check_spf(domain).__dict__,
            "dmarc": check_dmarc(domain).__dict__,
            "dkim": check_dkim(domain, dkim_cfg).__dict__,
            "expiry": check_expiry(domain).__dict__,
        },
    }


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="DNS analysis monitor with confidence metadata")
    p.add_argument("--domain", help="Single domain to analyse")
    p.add_argument("--input-file", help="Batch file with one domain per line")
    p.add_argument("--expected-ns", default=str(DEFAULT_EXPECTED_NS_FILE), help="Expected nameserver policy JSON")
    p.add_argument("--dkim-selectors", default=str(DEFAULT_DKIM_SELECTORS_FILE), help="Per-domain DKIM selectors JSON")
    p.add_argument("--output", choices=["json"], default="json")
    p.add_argument("--version", action="version", version=f"domain-security-monitor {VERSION}")
    return p.parse_args()


def load_domains(args: argparse.Namespace) -> list[str]:
    items: list[str] = []
    if args.domain:
        items.append(args.domain.strip().lower())
    if args.input_file:
        for ln in Path(args.input_file).read_text(encoding="utf-8").splitlines():
            v = ln.strip().lower()
            if not v or v.startswith("#"):
                continue
            items.append(v)

    dedup = []
    seen = set()
    for d in items:
        if d in seen:
            continue
        seen.add(d)
        dedup.append(d)
    return dedup


def main() -> int:
    args = parse_args()
    domains = load_domains(args)
    if not domains:
        print(json.dumps({"error": "provide --domain or --input-file"}, indent=2))
        return 2

    expected_cfg = load_json(Path(args.expected_ns), {"default": [], "domain_overrides": {}})
    dkim_cfg = load_json(Path(args.dkim_selectors), {})

    results = [analyse_domain(d, expected_cfg, dkim_cfg) for d in domains]
    print(json.dumps({"count": len(results), "results": results}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
