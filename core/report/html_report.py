import html
import os
from datetime import datetime

OUTPUT_DIR = os.path.join(
    os.path.dirname(os.path.dirname(os.path.dirname(__file__))), "output"
)

RISK_COLORS = {
    "CRITICAL": "#ff4d4d",
    "HIGH": "#ff9900",
    "MEDIUM": "#ffcc00",
    "LOW": "#33cc33"
}

HTML_TEMPLATE = """<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<title>AutoRecon Report - {target}</title>
<style>
  body {{ font-family: 'Courier New', monospace; background: #0d1117; color: #c9d1d9; padding: 30px; }}
  h1 {{ color: #58a6ff; border-bottom: 2px solid #30363d; padding-bottom: 10px; }}
  h2 {{ color: #79c0ff; margin-top: 30px; }}
  table {{ width: 100%; border-collapse: collapse; margin-top: 10px; }}
  th, td {{ border: 1px solid #30363d; padding: 8px 12px; text-align: left; word-break: break-all; }}
  th {{ background: #161b22; color: #58a6ff; }}
  tr:nth-child(even) {{ background: #161b22; }}
  .badge {{ padding: 3px 10px; border-radius: 4px; font-weight: bold; color: #000; }}
  .meta {{ color: #8b949e; font-size: 14px; }}
</style>
</head>
<body>
  <h1>AutoRecon Report</h1>
  <p class="meta">Target: <b>{target}</b> | Generated: {date}</p>

  <h2>WHOIS</h2>
  {whois_table}

  <h2>DNS Records</h2>
  {dns_table}

  <h2>Subdomains Found ({subdomain_count})</h2>
  {subdomain_table}

  <h2>Open Ports</h2>
  {ports_table}

  <h2>Vulnerability Risk Assessment</h2>
  <p class="meta">Based on version matching (CPE). Shows potential exposure, not confirmed exploitability.</p>
  {vuln_table}

</body>
</html>
"""


def esc(value) -> str:
    """Escape any value before inserting into HTML."""
    return html.escape(str(value))


def dict_to_table(data: dict) -> str:
    if not data:
        return "<p>No data</p>"
    rows = "".join(
        f"<tr><th>{esc(k)}</th><td>{esc(v)}</td></tr>" for k, v in data.items()
    )
    return f"<table>{rows}</table>"


def dns_to_table(dns_data: dict) -> str:
    records = dns_data.get("records", {})
    if not records:
        return "<p>No data</p>"
    rows = ""
    for rtype, values in records.items():
        val_str = ", ".join(esc(v) for v in values) if values else "-"
        rows += f"<tr><th>{esc(rtype)}</th><td>{val_str}</td></tr>"
    return f"<table>{rows}</table>"


def subdomains_to_table(sub_data: dict) -> str:
    subs = sub_data.get("subdomains", [])
    if not subs:
        return "<p>No subdomains found</p>"
    rows = "".join(
        f"<tr><td>{esc(s['subdomain'])}</td>"
        f"<td>{', '.join(esc(ip) for ip in s['ips'])}</td></tr>"
        for s in subs
    )
    return f"<table><tr><th>Subdomain</th><th>IP(s)</th></tr>{rows}</table>"


def ports_to_table(port_data: dict) -> str:
    ports = port_data.get("open_ports", [])
    if not ports:
        return "<p>No open ports found</p>"
    rows = "".join(
        f"<tr><td>{esc(p['port'])}</td><td>{esc(p['state'])}</td><td>{esc(p['service'])}</td></tr>"
        for p in ports
    )
    return f"<table><tr><th>Port</th><th>State</th><th>Service</th></tr>{rows}</table>"


def vuln_to_table(classified_data: dict) -> str:
    classified = classified_data.get("classified", {})
    if not classified:
        return "<p>No vulnerability data (no service versions detected)</p>"

    rows = ""
    for port, d in classified.items():
        color = RISK_COLORS.get(d["risk_level"], "#ccc")
        rows += (
            f"<tr><td>{esc(port)}</td><td>{esc(d['service'])}</td>"
            f"<td>{esc(d['version'])}</td><td>{esc(d['max_cvss'])}</td>"
            f"<td><span class='badge' style='background:{color}'>{esc(d['risk_level'])}</span></td></tr>"
        )
    return (
        "<table><tr><th>Port</th><th>Service</th><th>Version</th>"
        f"<th>Max CVSS</th><th>Risk</th></tr>{rows}</table>"
    )


def generate_html_report(target: str, data: dict) -> str:
    os.makedirs(OUTPUT_DIR, exist_ok=True)

    whois_data = data.get("whois", {}).get("data", {})
    dns_data   = data.get("dns", {})
    sub_data   = data.get("subdomains", {})
    port_data  = data.get("ports", {})
    vuln_data  = data.get("vulnerabilities", {})

    page = HTML_TEMPLATE.format(
        target=esc(target),
        date=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        whois_table=dict_to_table(whois_data),
        dns_table=dns_to_table(dns_data),
        subdomain_count=esc(sub_data.get("found", 0)),
        subdomain_table=subdomains_to_table(sub_data),
        ports_table=ports_to_table(port_data),
        vuln_table=vuln_to_table(vuln_data),
    )

    filename = f"report_{target.replace('.', '_')}.html"
    filepath = os.path.join(OUTPUT_DIR, filename)

    with open(filepath, "w", encoding="utf-8") as f:
        f.write(page)

    print(f"[+] HTML report saved → {filepath}")
    return filepath
