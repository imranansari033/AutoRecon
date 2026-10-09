import re
import time
import requests

NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

# Product name in banner → CPE template (exact product matching, no false positives)
CPE_MAP = {
    "OpenSSH": "cpe:2.3:a:openbsd:openssh:{v}",
    "Apache":  "cpe:2.3:a:apache:http_server:{v}",
    "nginx":   "cpe:2.3:a:nginx:nginx:{v}",
    "vsftpd":  "cpe:2.3:a:vsftpd_project:vsftpd:{v}",
}


def banner_to_cpe(version: str):
    """
    'OpenSSH_6.6.1p1' -> 'cpe:2.3:a:openbsd:openssh:6.6.1'
    'Apache/2.4.7'    -> 'cpe:2.3:a:apache:http_server:2.4.7'
    Returns None if product is not in CPE_MAP.
    """
    for product, template in CPE_MAP.items():
        if product.lower() in version.lower():
            m = re.search(r"(\d+\.\d+(?:\.\d+)?)", version)
            if m:
                return template.format(v=m.group(1))
    return None


def search_cves(version: str, max_results: int = 5) -> dict:
    """Search NVD by CPE (exact product + version), return top CVEs by CVSS score."""
    cpe = banner_to_cpe(version)
    if not cpe:
        return {"status": "error", "message": f"No CPE mapping for '{version}'"}

    params = {"virtualMatchString": cpe, "resultsPerPage": 100}

    try:
        response = requests.get(NVD_API_URL, params=params, timeout=15)

        if response.status_code == 200:
            result = parse_cve_response(response.json(), cpe)
            # Sort highest CVSS first so the worst CVE is always included
            result["cves"].sort(
                key=lambda c: c["score"] if isinstance(c["score"], (int, float)) else 0,
                reverse=True
            )
            result["cves"] = result["cves"][:max_results]
            result["showing"] = len(result["cves"])
            return result

        elif response.status_code == 403:
            return {"status": "error", "message": "Rate limited by NVD API. Wait 30s and retry."}

        return {"status": "error", "message": f"NVD API returned {response.status_code}"}

    except requests.exceptions.Timeout:
        return {"status": "error", "message": "NVD API request timed out"}
    except Exception as e:
        return {"status": "error", "message": str(e)}


def parse_cve_response(data: dict, keyword: str) -> dict:
    """Extract useful fields from raw NVD API response."""
    cves = []

    for item in data.get("vulnerabilities", []):
        cve = item.get("cve", {})
        cve_id = cve.get("id", "N/A")

        descriptions = cve.get("descriptions", [])
        description = next(
            (d["value"] for d in descriptions if d.get("lang") == "en"),
            "No description available"
        )

        score, severity = extract_cvss_score(cve)

        cves.append({
            "cve_id": cve_id,
            "score": score,
            "severity": severity,
            "description": description[:200]
        })

    return {
        "status": "success",
        "keyword": keyword,
        "total_found": data.get("totalResults", 0),
        "showing": len(cves),
        "cves": cves
    }


def extract_cvss_score(cve: dict) -> tuple:
    """Extract CVSS v3 score and severity. Falls back to v2."""
    metrics = cve.get("metrics", {})

    v3_list = metrics.get("cvssMetricV31", []) or metrics.get("cvssMetricV30", [])
    if v3_list:
        cvss_data = v3_list[0].get("cvssData", {})
        return cvss_data.get("baseScore", "N/A"), cvss_data.get("baseSeverity", "N/A")

    v2_list = metrics.get("cvssMetricV2", [])
    if v2_list:
        cvss_data = v2_list[0].get("cvssData", {})
        return cvss_data.get("baseScore", "N/A"), v2_list[0].get("baseSeverity", "N/A")

    return "N/A", "N/A"


def bulk_cve_lookup(services: list) -> dict:
    """
    Run CVE lookup for multiple services detected by service_detect.
    services: [{"port": 22, "service": "SSH", "version": "OpenSSH_6.6.1p1"}, ...]
    """
    results = {}

    for svc in services:
        version = svc.get("version")
        port    = svc.get("port")
        service = svc.get("service", "Unknown")

        if not version or version == "N/A":
            print(f"  [~] Port {port} ({service}) — no version, skipping")
            continue

        print(f"  [*] Searching CVEs for: {version}")

        cve_result = search_cves(version, max_results=5)
        results[port] = {
            "service": service,
            "version": version,
            "cve_data": cve_result
        }

        time.sleep(6)  # NVD limit without API key: 5 requests / 30 sec

    return {"status": "success", "results": results}


def print_cve_results(bulk_result: dict):
    print("\n" + "=" * 60)
    print("  CVE LOOKUP RESULTS")
    print("=" * 60)

    for port, data in bulk_result["results"].items():
        service  = data["service"]
        version  = data["version"]
        cve_data = data["cve_data"]

        print(f"\n  Port {port} — {service} ({version})")
        print(f"  {'─' * 50}")

        if cve_data["status"] == "error":
            print(f"  [!] Error: {cve_data['message']}")
            continue

        total = cve_data["total_found"]
        print(f"  Total CVEs found: {total} (showing top {cve_data['showing']} by score)")

        if total == 0:
            print("  [✓] No known CVEs found")
            continue

        icons = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🟢"}
        for cve in cve_data["cves"]:
            icon = icons.get(str(cve["severity"]).upper(), "⚪")
            print(f"\n  {icon} {cve['cve_id']}")
            print(f"     Score   : {cve['score']} ({cve['severity']})")
            print(f"     Summary : {cve['description'][:120]}...")

    print("\n" + "=" * 60 + "\n")


if __name__ == "__main__":
    # Simulated service_detect output for scanme.nmap.org
    services = [
        {"port": 22, "service": "SSH",  "version": "OpenSSH_6.6.1p1"},
        {"port": 80, "service": "HTTP", "version": "Apache/2.4.7"},
    ]

    print("[*] Running CVE lookup on detected services...\n")
    result = bulk_cve_lookup(services)
    print_cve_results(result)
