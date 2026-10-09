#!/usr/bin/env python3
import argparse
import sys
import time

from core.passive.whois_enum import whois_lookup
from core.passive.dns_enum import dns_lookup
from core.passive.subdomain_enum import subdomain_enum
from core.active.port_scanner import port_scan
from core.active.service_detect import service_detect
from core.vuln.cve_lookup import bulk_cve_lookup
from core.vuln.risk_classifier import classify_scan_results, print_classified
from core.report.json_report import generate_json_report
from core.report.html_report import generate_html_report


BANNER = r"""
   _         _        ____                     
  / \  _   _| |_ ___ |  _ \ ___  ___ ___  _ __  
 / _ \| | | | __/ _ \| |_) / _ \/ __/ _ \| '_ \ 
/ ___ \ |_| | || (_) |  _ <  __/ (_| (_) | | | |
/_/   \_\__,_|\__\___/|_| \_\___|\___\___/|_| |_|

         Automated Recon & Vuln Assessment
"""


def run_passive(target: str) -> dict:
    print("\n[PHASE 1] Passive Recon")
    print("-" * 50)

    print("[*] Running WHOIS lookup...")
    whois_data = whois_lookup(target)

    print("[*] Running DNS enumeration...")
    dns_data = dns_lookup(target)

    print("[*] Running subdomain enumeration...")
    sub_data = subdomain_enum(target)

    return {"whois": whois_data, "dns": dns_data, "subdomains": sub_data}


def run_active(target: str, port_range: tuple, threads: int) -> dict:
    print("\n[PHASE 2] Active Scanning")
    print("-" * 50)

    print("[*] Running port scan...")
    port_data = port_scan(target, port_range, threads=threads)

    if port_data["status"] == "error":
        print(f"[!] {port_data['message']}")
        return {"ports": port_data, "services": {"status": "error", "services": []}}

    if port_data["total_open"] == 0:
        print("[!] No open ports found, skipping service detection")
        return {"ports": port_data, "services": {"status": "success", "services": []}}

    print("[*] Running service/banner detection...")
    service_data = service_detect(target, port_data["open_ports"])

    return {"ports": port_data, "services": service_data}


def run_vuln_assessment(service_data: dict) -> dict:
    print("\n[PHASE 3] Vulnerability Assessment")
    print("-" * 50)

    services = service_data.get("services", [])
    if not services:
        print("[!] No services to assess, skipping CVE lookup")
        return {"status": "success", "classified": {}}

    # Build input for bulk_cve_lookup: [{"port":.., "service":.., "version":..}]
    service_list = [
        {"port": s["port"], "service": s.get("service", "Unknown"), "version": s.get("version")}
        for s in services
    ]

    print("[*] Querying NVD for CVEs on detected services...")
    cve_results = bulk_cve_lookup(service_list)

    print("[*] Running ML risk classification...")
    classified = classify_scan_results(cve_results)
    print_classified(classified)

    return classified


def build_reports(target: str, all_data: dict, output: str):
    print("\n[PHASE 4] Report Generation")
    print("-" * 50)

    if output in ("json", "both"):
        generate_json_report(target, all_data)

    if output in ("html", "both"):
        generate_html_report(target, all_data)


def main():
    parser = argparse.ArgumentParser(
        description="AutoRecon — Automated Recon & Vulnerability Assessment Framework"
    )
    parser.add_argument("--target", required=True, help="Target domain or IP")
    parser.add_argument(
        "--mode", choices=["passive", "active", "full"], default="full",
        help="Scan mode (default: full)"
    )
    parser.add_argument(
        "--ports", default="1-1024",
        help="Port range for active scan, e.g. 1-1024 (default) or 1-65535"
    )
    parser.add_argument(
        "--threads", type=int, default=100,
        help="Number of threads for port scanning (default: 100)"
    )
    parser.add_argument(
        "--output", choices=["json", "html", "both", "none"], default="html",
        help="Report output format (default: html)"
    )

    args = parser.parse_args()

    print(BANNER)
    print(f"[*] Target : {args.target}")
    print(f"[*] Mode   : {args.mode}")
    start_time = time.time()

    all_data = {}

    try:
        if args.mode in ("passive", "full"):
            all_data.update(run_passive(args.target))

        if args.mode in ("active", "full"):
            start, end = map(int, args.ports.split("-"))
            active_data = run_active(args.target, (start, end), args.threads)
            all_data.update(active_data)

        if args.mode == "full":
            vuln_data = run_vuln_assessment(all_data.get("services", {}))
            all_data["vulnerabilities"] = vuln_data

        if args.output != "none":
            build_reports(args.target, all_data, args.output)

    except KeyboardInterrupt:
        print("\n[!] Scan interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"\n[!] Unexpected error: {e}")
        sys.exit(1)

    elapsed = time.time() - start_time
    print(f"\n[+] Scan completed in {elapsed:.2f} seconds")


if __name__ == "__main__":
    main()
