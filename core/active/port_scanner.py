import socket
import threading
from queue import Queue

# Common ports with service names
COMMON_PORTS = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    111: "RPCBind",
    135: "MSRPC",
    139: "NetBIOS",
    143: "IMAP",
    443: "HTTPS",
    445: "SMB",
    993: "IMAPS",
    995: "POP3S",
    1723: "PPTP",
    3306: "MySQL",
    3389: "RDP",
    5900: "VNC",
    8080: "HTTP-Alt",
    8443: "HTTPS-Alt",
    8888: "HTTP-Alt2",
    27017: "MongoDB",
    5432: "PostgreSQL",
    6379: "Redis",
    9200: "Elasticsearch"
}

open_ports = []
lock = threading.Lock()


def scan_port(ip: str, port: int, timeout: float = 1.0):
    """Try to connect to a port. If successful, the port is open."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)

        result = sock.connect_ex((ip, port))

        sock.close()

        # connect_ex() returns 0 when connection succeeds
        if result == 0:
            service = COMMON_PORTS.get(port, "Unknown")

            with lock:
                open_ports.append({
                    "port": port,
                    "service": service,
                    "state": "open"
                })

                print(f"  [+] {port:<6} OPEN   → {service}")

    except Exception:
        pass


def port_scan(
    target: str,
    port_range: tuple = (1, 1024),
    threads: int = 100
) -> dict:
    """
    Scan ports on a target IP/domain.

    port_range:
        Tuple containing start and end port.

    threads:
        Number of concurrent worker threads.
    """

    global open_ports

    # Reset results for every scan
    open_ports = []

    # Resolve domain to IP
    try:
        ip = socket.gethostbyname(target)

    except socket.gaierror:
        return {
            "status": "error",
            "message": f"Cannot resolve: {target}"
        }

    start_port, end_port = port_range

    # Validate port range
    if start_port < 1 or end_port > 65535 or start_port > end_port:
        return {
            "status": "error",
            "message": "Invalid port range. Use 1-65535."
        }

    total = end_port - start_port + 1

    print(f"\n[*] Target  : {target} ({ip})")
    print(f"[*] Range   : {start_port} - {end_port} ({total} ports)")
    print(f"[*] Threads : {threads}\n")

    queue = Queue()

    # Add ports to queue
    for port in range(start_port, end_port + 1):
        queue.put(port)

    def worker():
        while True:
            try:
                port = queue.get_nowait()
            except Exception:
                break

            try:
                scan_port(ip, port)
            finally:
                queue.task_done()

    # Create threads
    thread_list = []

    for _ in range(threads):
        t = threading.Thread(target=worker)
        t.daemon = True
        t.start()
        thread_list.append(t)

    # Wait until all queued ports are processed
    queue.join()

    # Wait for worker threads
    for t in thread_list:
        t.join()

    # Sort results by port number
    open_ports.sort(key=lambda x: x["port"])

    return {
        "status": "success",
        "target": target,
        "ip": ip,
        "range": f"{start_port}-{end_port}",
        "open_ports": open_ports,
        "total_open": len(open_ports)
    }


def print_scan_results(result: dict):
    """Pretty print scan results."""

    if result["status"] == "error":
        print(f"\n[!] Scan failed: {result['message']}")
        return

    print("\n" + "=" * 45)
    print("  PORT SCAN RESULTS")
    print("=" * 45)

    print(f"  Target : {result['target']} ({result['ip']})")
    print(f"  Range  : {result['range']}")
    print(f"  Open   : {result['total_open']} ports")

    print("-" * 45)
    print(f"  {'PORT':<8} {'STATE':<10} {'SERVICE'}")
    print("-" * 45)

    for entry in result["open_ports"]:
        print(
            f"  {entry['port']:<8} "
            f"{entry['state']:<10} "
            f"{entry['service']}"
        )

    print("=" * 45 + "\n")


if __name__ == "__main__":

    target = input("Enter target (IP or domain): ").strip()

    print("\n1. Common ports (1-1024)")
    print("2. Custom range")
    print("3. Top common ports only")

    choice = input("Choose: ").strip()

    # Option 1: Scan ports 1-1024
    if choice == "1":

        result = port_scan(
            target,
            (1, 1024)
        )

    # Option 2: Custom port range
    elif choice == "2":

        try:
            start = int(input("Start port: "))
            end = int(input("End port: "))

            result = port_scan(
                target,
                (start, end)
            )

        except ValueError:

            result = {
                "status": "error",
                "message": "Port numbers must be integers."
            }

    # Option 3: Scan only common ports
    elif choice == "3":

        # No global declaration needed here
        open_ports = []

        try:
            ip = socket.gethostbyname(target)

            print(
                f"\n[*] Scanning {len(COMMON_PORTS)} "
                f"known ports on {target} ({ip})\n"
            )

            for port in COMMON_PORTS:
                scan_port(ip, port)

            # Sort results
            open_ports.sort(key=lambda x: x["port"])

            result = {
                "status": "success",
                "target": target,
                "ip": ip,
                "range": "common ports",
                "open_ports": open_ports,
                "total_open": len(open_ports)
            }

        except socket.gaierror:

            result = {
                "status": "error",
                "message": f"Cannot resolve: {target}"
            }

    # Invalid menu choice
    else:

        result = {
            "status": "error",
            "message": "Invalid choice. Please select 1, 2, or 3."
        }

    # Display results
    print_scan_results(result)
