import socket
import re

# Probes to send for specific ports to trigger a banner response
PORT_PROBES = {
    21:   b"",                        # FTP sends banner automatically
    22:   b"",                        # SSH sends banner automatically
    25:   b"EHLO test\r\n",           # SMTP
    80:   b"HEAD / HTTP/1.0\r\n\r\n", # HTTP
    443:  b"",                        # HTTPS (banner grab limited without TLS)
    110:  b"",                        # POP3 sends banner automatically
    143:  b"",                        # IMAP sends banner automatically
    3306: b"",                        # MySQL sends banner automatically
    6379: b"INFO\r\n",                # Redis
    27017: b"",                       # MongoDB
}

DEFAULT_PROBE = b"HEAD / HTTP/1.0\r\n\r\n"


def grab_banner(ip: str, port: int, timeout: float = 2.0) -> dict:
    """
    Connect to open port and grab the service banner.
    Returns version/service info if available.
    """
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((ip, port))

        # Send probe if we have one for this port
        probe = PORT_PROBES.get(port, DEFAULT_PROBE)
        if probe:
            sock.send(probe)

        # Receive banner (up to 1024 bytes)
        banner = sock.recv(1024).decode("utf-8", errors="ignore").strip()
        sock.close()

        # Clean up banner — remove extra whitespace/newlines
        banner_clean = " | ".join(
            line.strip() for line in banner.splitlines() if line.strip()
        )[:200]  # limit to 200 chars

        return {
            "status": "success",
            "port": port,
            "banner": banner_clean,
            "version": extract_version(banner_clean)
        }

    except socket.timeout:
        return {"status": "no_banner", "port": port, "banner": "No response", "version": None}
    except ConnectionRefusedError:
        return {"status": "closed", "port": port, "banner": "Port closed", "version": None}
    except Exception as e:
        return {"status": "error", "port": port, "banner": str(e), "version": None}


def extract_version(banner: str) -> str:
    """
    Try to extract version string from banner using regex.
    Examples:
      'SSH-2.0-OpenSSH_8.9p1'  → 'OpenSSH_8.9p1'
      'Apache/2.4.41'          → 'Apache/2.4.41'
      'nginx/1.18.0'           → 'nginx/1.18.0'
    """
    patterns = [
        r"(OpenSSH[\w._-]+)",           # SSH
        r"(Apache/[\d.]+)",             # Apache
        r"(nginx/[\d.]+)",              # Nginx
        r"(vsftpd[\s/][\d.]+)",         # FTP
        r"(MySQL[\s/][\d.]+)",          # MySQL
        r"(Microsoft-IIS/[\d.]+)",      # IIS
        r"(PHP/[\d.]+)",                # PHP
        r"(OpenSSL/[\d.]+)",            # OpenSSL
        r"(\d+\.\d+\.\d+)",             # Generic version x.x.x
    ]

    for pattern in patterns:
        match = re.search(pattern, banner, re.IGNORECASE)
        if match:
            return match.group(1)

    return None


def service_detect(target: str, open_ports: list) -> dict:
    """
    Run banner grabbing on all open ports from port scan results.
    open_ports: list of dicts from port_scanner → [{"port": 80, "service": "HTTP"}, ...]
    """
    try:
        ip = socket.gethostbyname(target)
    except socket.gaierror:
        return {"status": "error", "message": f"Cannot resolve: {target}"}

    print(f"\n[*] Banner grabbing on {target} ({ip})")
    print(f"[*] Probing {len(open_ports)} open ports...\n")

    results = []
    for entry in open_ports:
        port = entry["port"]
        service = entry.get("service", "Unknown")
        print(f"  [~] Probing port {port} ({service})...")

        banner_result = grab_banner(ip, port)
        banner_result["service"] = service  # attach service name

        results.append(banner_result)

    return {
        "status": "success",
        "target": target,
        "ip": ip,
        "services": results
    }


def print_service_results(result: dict):
    if result["status"] == "error":
        print(f"[!] {result['message']}")
        return

    print("\n" + "="*55)
    print("  SERVICE DETECTION RESULTS")
    print("="*55)
    print(f"  Target: {result['target']} ({result['ip']})")
    print("-"*55)
    print(f"  {'PORT':<7} {'SERVICE':<12} {'VERSION':<18} BANNER")
    print("-"*55)

    for s in result["services"]:
        port    = s.get("port", "?")
        service = s.get("service", "Unknown")
        version = s.get("version") or "N/A"
        banner  = s.get("banner", "")[:40]  # truncate for display
        print(f"  {port:<7} {service:<12} {version:<18} {banner}")

    print("="*55 + "\n")


if __name__ == "__main__":
    # Simulate using output from port_scanner
    from port_scanner import port_scan

    target = input("Enter target (IP or domain): ")
    print("\n[*] Running port scan first...")

    scan_result = port_scan(target, (1, 1024), threads=100)

    if scan_result["status"] == "error":
        print(f"[!] {scan_result['message']}")
    else:
        detect_result = service_detect(target, scan_result["open_ports"])
        print_service_results(detect_result)
