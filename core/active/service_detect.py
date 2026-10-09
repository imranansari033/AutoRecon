import re
import socket
import ssl

TLS_PORTS = {443, 8443}

PORT_PROBES = {
    25:   b"EHLO test\r\n",
    6379: b"INFO\r\n",
}


def http_probe(host: str) -> bytes:
    return (
        f"HEAD / HTTP/1.1\r\nHost: {host}\r\n"
        f"User-Agent: AutoRecon\r\nConnection: close\r\n\r\n"
    ).encode()


def grab_banner(ip: str, port: int, host: str = None, timeout: float = 3.0) -> dict:
    """Connect to open port and grab the service banner (TLS-aware)."""
    host = host or ip
    try:
        sock = socket.create_connection((ip, port), timeout=timeout)
        sock.settimeout(timeout)

        if port in TLS_PORTS:
            # Recon tool: we want the banner even from self-signed/invalid certs
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            sock = ctx.wrap_socket(sock, server_hostname=host)

        if port in PORT_PROBES:
            probe = PORT_PROBES[port]
        elif port in TLS_PORTS or port in (80, 8080, 8888):
            probe = http_probe(host)
        else:
            probe = b""  # SSH, FTP, POP3... send banner automatically

        if probe:
            sock.send(probe)

        banner = sock.recv(1024).decode("utf-8", errors="ignore").strip()
        sock.close()

        banner_clean = " | ".join(
            line.strip() for line in banner.splitlines() if line.strip()
        )[:300]

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


def extract_version(banner: str):
    """
    'SSH-2.0-OpenSSH_8.9p1' -> 'OpenSSH_8.9p1'
    'Server: Apache/2.4.41' -> 'Apache/2.4.41'
    """
    patterns = [
        r"(OpenSSH[\w._-]+)",
        r"(Apache/[\d.]+)",
        r"(nginx/[\d.]+)",
        r"(vsftpd[\s/][\d.]+)",
        r"(MySQL[\s/][\d.]+)",
        r"(Microsoft-IIS/[\d.]+)",
        r"(PHP/[\d.]+)",
        r"(OpenSSL/[\d.]+)",
    ]
    for pattern in patterns:
        match = re.search(pattern, banner, re.IGNORECASE)
        if match:
            return match.group(1)

    # Generic x.y.z only from the Server header (avoids matching dates/IPs)
    server = re.search(r"Server:\s*([^|]+)", banner, re.IGNORECASE)
    if server:
        generic = re.search(r"(\d+\.\d+\.\d+)", server.group(1))
        if generic:
            return server.group(1).strip()
    return None


def service_detect(target: str, open_ports: list) -> dict:
    """Run banner grabbing on all open ports from port scan results."""
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

        banner_result = grab_banner(ip, port, host=target)
        banner_result["service"] = service
        results.append(banner_result)

    return {"status": "success", "target": target, "ip": ip, "services": results}


def print_service_results(result: dict):
    if result["status"] == "error":
        print(f"[!] {result['message']}")
        return

    print("\n" + "=" * 60)
    print("  SERVICE DETECTION RESULTS")
    print("=" * 60)
    print(f"  Target: {result['target']} ({result['ip']})")
    print("-" * 60)
    print(f"  {'PORT':<7} {'SERVICE':<12} {'VERSION':<18} BANNER")
    print("-" * 60)

    for s in result["services"]:
        version = s.get("version") or "N/A"
        banner  = s.get("banner", "")[:40]
        print(f"  {s.get('port', '?'):<7} {s.get('service', 'Unknown'):<12} {version:<18} {banner}")

    print("=" * 60 + "\n")


if __name__ == "__main__":
    from port_scanner import port_scan

    target = input("Enter target (IP or domain): ")
    print("\n[*] Running port scan first...")

    scan_result = port_scan(target, (1, 1024), threads=100)

    if scan_result["status"] == "error":
        print(f"[!] {scan_result['message']}")
    else:
        detect_result = service_detect(target, scan_result["open_ports"])
        print_service_results(detect_result)
