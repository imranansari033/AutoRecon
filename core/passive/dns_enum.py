import dns.resolver
import dns.reversename

def dns_lookup(target: str) -> dict:
    """
    Enumerate common DNS records for a domain.
    Returns structured dict with all record types.
    """

    # Record types we want to fetch
    record_types = ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA"]
    
    results = {}

    for record_type in record_types:
        try:
            answers = dns.resolver.resolve(target, record_type)
            results[record_type] = [str(r) for r in answers]

        except dns.resolver.NoAnswer:
            results[record_type] = []          # Record doesn't exist
        except dns.resolver.NXDOMAIN:
            return {"status": "error", "message": f"Domain '{target}' does not exist"}
        except dns.resolver.Timeout:
            results[record_type] = ["timeout"]
        except Exception as e:
            results[record_type] = [f"error: {str(e)}"]

    return {"status": "success", "domain": target, "records": results}


def reverse_dns(ip: str) -> dict:
    """PTR lookup — IP to hostname."""
    try:
        rev_name = dns.reversename.from_address(ip)
        answer = dns.resolver.resolve(rev_name, "PTR")
        return {"status": "success", "ip": ip, "hostname": str(answer[0])}
    except Exception as e:
        return {"status": "error", "message": str(e)}


def print_dns(result: dict):
    """Pretty print DNS results to terminal."""
    if result["status"] == "error":
        print(f"[!] DNS Enum failed: {result['message']}")
        return

    print("\n" + "="*40)
    print("  DNS ENUMERATION RESULTS")
    print("="*40)
    print(f"  Domain: {result['domain']}")
    print("-"*40)

    for record_type, values in result["records"].items():
        if values:
            print(f"\n  [{record_type}]")
            for v in values:
                print(f"    → {v}")
        else:
            print(f"\n  [{record_type}] — No records found")

    print("\n" + "="*40 + "\n")


if __name__ == "__main__":
    print("1. Domain DNS lookup")
    print("2. Reverse DNS (IP → hostname)")
    choice = input("Choose: ")

    if choice == "1":
        target = input("Enter domain: ")
        result = dns_lookup(target)
        print_dns(result)

    elif choice == "2":
        ip = input("Enter IP: ")
        result = reverse_dns(ip)
        if result["status"] == "success":
            print(f"\n[+] {result['ip']} → {result['hostname']}")
        else:
            print(f"[!] {result['message']}")
