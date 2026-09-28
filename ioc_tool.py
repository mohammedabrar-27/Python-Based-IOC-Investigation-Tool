#!/usr/bin/env python3

import argparse
import base64
import hashlib
import ipaddress
import json
import os
import re
from pathlib import Path
from urllib.parse import urlparse

import requests
from dotenv import load_dotenv

TIMEOUT = 15


def detect_type(ioc):
    if re.fullmatch(r"[a-fA-F0-9]{64}", ioc):
        return "sha256"
    try:
        ipaddress.ip_address(ioc)
        return "ip"
    except ValueError:
        pass

    value = ioc if "://" in ioc else "https://" + ioc
    parsed = urlparse(value)
    if parsed.scheme in ("http", "https") and parsed.hostname:
        if "://" in ioc or parsed.path not in ("", "/") or parsed.query or parsed.fragment:
            return "url"
        if "." in parsed.hostname:
            return "domain"
    raise ValueError("Enter a valid IP, domain, URL or SHA256.")


def get_json(url, *, headers=None, params=None):
    response = requests.get(url, headers=headers, params=params, timeout=TIMEOUT)
    response.raise_for_status()
    return response.json()


def file_sha256(path):
    digest = hashlib.sha256()
    with open(path, "rb") as file:
        for chunk in iter(lambda: file.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def lookup(name, url, key, headers, params=None):
    if not key:
        return {"source": name, "status": "SKIPPED", "error": "API key not configured", "data": {}}
    try:
        data = get_json(url, headers=headers(key), params=params)
        return {"source": name, "status": "OK", "data": data, "error": None}
    except requests.RequestException as exc:
        return {"source": name, "status": "ERROR", "data": {}, "error": str(exc)}
    except ValueError as exc:
        return {"source": name, "status": "ERROR", "data": {}, "error": f"Invalid API response: {exc}"}


def enrich(ioc, kind):
    vt_key = os.getenv("VIRUSTOTAL_API_KEY")
    if kind == "ip":
        vt_path = "ip_addresses/" + ioc
    elif kind == "domain":
        vt_path = "domains/" + ioc
    elif kind == "sha256":
        vt_path = "files/" + ioc
    else:
        url_id = base64.urlsafe_b64encode(ioc.encode()).decode().rstrip("=")
        vt_path = "urls/" + url_id

    vt = lookup(
        "VirusTotal", "https://www.virustotal.com/api/v3/" + vt_path, vt_key,
        lambda key: {"x-apikey": key, "accept": "application/json"},
    )
    if vt["status"] == "OK":
        attrs = vt["data"].get("data", {}).get("attributes", {})
        stats = attrs.get("last_analysis_stats") or {}
        vt["data"] = {"reputation": attrs.get("reputation"), **stats,
                       "country": attrs.get("country"), "asn": attrs.get("asn"),
                       "as_owner": attrs.get("as_owner"), "tags": attrs.get("tags")}

    if kind == "ip":
        abuse = lookup(
            "AbuseIPDB", "https://api.abuseipdb.com/api/v2/check",
            os.getenv("ABUSEIPDB_API_KEY"), lambda key: {"Key": key, "Accept": "application/json"},
            {"ipAddress": ioc, "maxAgeInDays": 90},
        )
        if abuse["status"] == "OK":
            data = abuse["data"].get("data", {})
            abuse["data"] = {"abuse_confidence_score": data.get("abuseConfidenceScore"),
                             "country": data.get("countryCode"), "usage_type": data.get("usageType"),
                             "isp": data.get("isp"), "total_reports": data.get("totalReports")}
    else:
        abuse = {"source": "AbuseIPDB", "status": "SKIPPED", "data": {},
                 "error": "Only supports IP addresses"}

    if kind in ("domain", "url"):
        query = f'page.domain:{ioc}' if kind == "domain" else f'page.url:"{ioc}"'
        scan = lookup(
            "urlscan.io", "https://urlscan.io/api/v1/search/", os.getenv("URLSCAN_API_KEY"),
            lambda key: {"api-key": key, "accept": "application/json"},
            {"q": query, "size": 5},
        )
        if scan["status"] == "OK":
            payload = scan["data"]
            scan["data"] = {"total": payload.get("total", 0), "scans": [
                {"url": item.get("page", {}).get("url"),
                 "malicious": item.get("verdicts", {}).get("overall", {}).get("malicious")}
                for item in payload.get("results", [])[:5]
            ]}
    else:
        scan = {"source": "urlscan.io", "status": "SKIPPED", "data": {},
                "error": "Only used for domains and URLs"}
    return [vt, abuse, scan]


def make_verdict(results):
    vt = next((r["data"] for r in results if r["source"] == "VirusTotal" and r["status"] == "OK"), {})
    abuse = next((r["data"] for r in results if r["source"] == "AbuseIPDB" and r["status"] == "OK"), {})
    malicious, suspicious = vt.get("malicious", 0), vt.get("suspicious", 0)
    score = abuse.get("abuse_confidence_score", 0)
    if malicious >= 3 or score >= 80:
        return "MALICIOUS"
    if malicious or suspicious or score >= 20:
        return "SUSPICIOUS"
    return "NO_MALICIOUS_DETECTIONS" if vt else "UNKNOWN"


def print_banner():
    print(r'''
  ============================================================
                 IOC INVESTIGATOR
   ____  ____   ___  _____ _____ ____   ____  ____   ___  ____
  |  _ \|  _ \ / _ \|  ___| ____/ ___| / ___/ ___| / _ \|  _ \
  | |_) | |_) | | | | |_  |  _| \___ \| |   \___ \| | | | |_) |
  |  __/|  _ <| |_| |  _| | |___ ___) | |___ ___) | |_| |  _ <
  |_|   |_| \_\___/|_|   |_____|____/ \____|____/ \___/|_| \_\
                 Created by PROFESSOR@27
  ------------------------------------------------------------
   Enter an IP, domain, URL, SHA256, or a local file path.
   Files stay local; the tool looks up only their SHA256 hash.
   Type exit, quit, or bye to close.
  ------------------------------------------------------------
''')


def main():
    load_dotenv()
    parser = argparse.ArgumentParser(description="Enrich an IP, domain, URL or SHA256.")
    parser.add_argument("ioc", nargs="?", help="Indicator to look up")
    parser.add_argument("--type", choices=("ip", "domain", "url", "sha256"), help="Override detected type")
    parser.add_argument("--json", action="store_true", help="Print results as JSON")
    args = parser.parse_args()

    def investigate(value):
        value = value.strip().strip('"')
        if not value:
            return
        if value.lower() in {"exit", "quit", "bye"}:
            return False

        path = Path(value).expanduser()
        if path.is_file():
            try:
                ioc = file_sha256(path)
            except OSError as exc:
                print(f"Cannot read file: {exc}")
                return True
            kind = "sha256"
            print(f"SHA256: {ioc}")
        else:
            ioc = value
            try:
                kind = args.type or detect_type(ioc)
            except ValueError as exc:
                print(f"Error: {exc}")
                return True

        results = enrich(ioc, kind)
        output = {"ioc": ioc, "ioc_type": kind, "verdict": make_verdict(results), "sources": results}
        if args.json:
            print(json.dumps(output, indent=2))
        else:
            print(f"\nIOC: {ioc} ({kind.upper()})")
            for result in results:
                print(f"\n[{result['source']}] {result['status']}")
                if result["error"]:
                    print(result["error"])
                for key, item in result["data"].items():
                    if item not in (None, "", [], {}):
                        print(f"{key.replace('_', ' ').title()}: {item}")
            print(f"\nVerdict: {output['verdict']}")
        return True

    if args.ioc:
        try:
            investigate(args.ioc)
        except KeyboardInterrupt:
            print("\nStopped.")
        return 0

    print_banner()
    while True:
        try:
            value = input("IOC: ")
            if investigate(value) is False:
                print("Goodbye.")
                break
        except (KeyboardInterrupt, EOFError):
            print("\nGoodbye.")
            break
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
