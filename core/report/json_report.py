import json
import os
from datetime import datetime

OUTPUT_DIR = os.path.join(
    os.path.dirname(os.path.dirname(os.path.dirname(__file__))), "output"
)


def generate_json_report(target: str, data: dict) -> str:
    """
    Combine all module results into one JSON report.
    data = {
        "whois": {...},
        "dns": {...},
        "subdomains": {...},
        "ports": {...},
        "services": {...},
        "vulnerabilities": {...},  # classified risk results
    }
    """
    os.makedirs(OUTPUT_DIR, exist_ok=True)

    report = {
        "target": target,
        "scan_date": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "results": data
    }

    filename = f"report_{target.replace('.', '_')}.json"
    filepath = os.path.join(OUTPUT_DIR, filename)

    with open(filepath, "w") as f:
        json.dump(report, f, indent=2, default=str)

    print(f"[+] JSON report saved → {filepath}")
    return filepath
