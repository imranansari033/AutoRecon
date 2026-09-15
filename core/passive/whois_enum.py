import whois
import json

def whois_lookup(target: str) -> dict:
    """
    Perform WHOIS lookup on a domain.
    Returns structured dict with key info.
    """
    try:
        w = whois.whois(target)

        result = {
            "domain": target,
            "registrar": w.registrar,
            "creation_date": str(w.creation_date),
            "expiration_date": str(w.expiration_date),
            "name_servers": w.name_servers,
            "emails": w.emails,
            "country": w.country,
            "org": w.org,
        }

        return {"status": "success", "data": result}

    except Exception as e:
        return {"status": "error", "message": str(e)}


def print_whois(result: dict):
    """Pretty print WHOIS result to terminal."""
    if result["status"] == "error":
        print(f"[!] WHOIS failed: {result['message']}")
        return

    data = result["data"]
    print("\n" + "="*40)
    print("  WHOIS LOOKUP RESULTS")
    print("="*40)
    for key, value in data.items():
        print(f"  {key.upper():<20}: {value}")
    print("="*40 + "\n")


# Quick test — run this file directly to test
if __name__ == "__main__":
    target = input("Enter domain: ")
    result = whois_lookup(target)
    print_whois(result)
