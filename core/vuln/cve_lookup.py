import requests
import json
import time

NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"


def search_cves(keyword: str, max_results: int = 5) -> dict:
    """
    Search NVD for CVEs matching a keyword (e.g. 'OpenSSH 6.6', 'Apache 2.4.7').
    Returns list of CVEs with id, score, severity, description.
    """
    params = {
        "keywordSearch": keyword,
        "resultsPerPage": max_results
    }

    try:
        response = requests.get(NVD_API_URL, params=params, timeout=10)

        if response.status_code == 200:
            data = response.json()
            return parse_cve_response(data, keyword)

        elif response.status_code == 403:
            return {"status": "error", "message": "Rate limited by NVD API. Wait 30s and retry."}

        else:
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

        # Get description (English only)
        descriptions = cve.get("descriptions", [])
        description = next(
            (d["value"] for d in descriptions if d.get("lang") == "en"),
            "No description available"
        )

        # Get CVSS score and severity
        score, severity = extract_cvss_score(cve)

        cves.append({
            "cve_id": cve_id,
            "score": score,
            "severity": severity,
            "description": description[:200]  # truncate
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

    # Try CVSSv3 first
    v3_list = metrics.get("cvssMetricV31", []) or metrics.get("cvssMetricV30", [])
    if v3_list:
        cvss_data = v3_list[0].get("cvssData", {})
        score    = cvss_data.get("baseScore", "N/A")
        severity = cvss_data.get("baseSeverity", "N/A")
        return score, severity

    # Fallback to CVSSv2
    v2_list = metrics.get("cvssMetricV2", [])
    if v2_list:
        cvss_data = v2_list[0].get("cvssData", {})
        score    = cvss_data.get("baseScore", "N/A")
        severity = v2_list[0].get("baseSeverity", "N/A")
        return score, severity

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

        # Build smart search keyword
        # e.g. "OpenSSH_6.6.1p1" → "OpenSSH 6.6.1"
        keyword = version.replace("_", " ").replace("/", " ")
        print(f"  [*] Searching CVEs for: {keyword}")

        cve_result = search_cves(keyword, max_results=5)
        results[port] = {
            "service": service,
            "version": version,
            "cve_data": cve_result
        }

        time.sleep(1)  # NVD rate limit — 1 req/sec without API key

    return {"status": "success", "results": results}


def print_cve_results(bulk_result: dict):
    print("\n" + "="*60)
    print("  CVE LOOKUP RESULTS")
    print("="*60)

    for port, data in bulk_result["results"].items():
        service = data["service"]
        version = data["version"]
        cve_data = data["cve_data"]

        print(f"\n  Port {port} — {service} ({version})")
        print(f"  {'─'*50}")

        if cve_data["status"] == "error":
            print(f"  [!] Error: {cve_data['message']}")
            continue

        total = cve_data["total_found"]
        print(f"  Total CVEs found: {total}")

        if total == 0:
            print("  [✓] No known CVEs found")
            continue

        for cve in cve_data["cves"]:
            severity_color = {
                "CRITICAL": "🔴",
                "HIGH":     "🟠",
                "MEDIUM":   "🟡",
                "LOW":      "🟢"
            }.get(str(cve["severity"]).upper(), "⚪")

            print(f"\n  {severity_color} {cve['cve_id']}")
            print(f"     Score    : {cve['score']} ({cve['severity']})")
            print(f"     Summary  : {cve['description'][:120]}...")

    print("\n" + "="*60 + "\n")


if __name__ == "__main__":
    # Simulate service_detect output
    services = [
        {"port": 22,  "service": "SSH",  "version": "OpenSSH_6.6.1p1"},
        {"port": 80,  "service": "HTTP", "version": "Apache/2.4.7"},
    ]

    print("[*] Running CVE lookup on detected services...\n")
    result = bulk_cve_lookup(services)
    print_cve_results(result)
