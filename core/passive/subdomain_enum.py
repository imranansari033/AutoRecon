import random
import string
import threading
from queue import Queue

import dns.resolver

DEFAULT_WORDLIST = [
    "www", "mail", "ftp", "admin", "api", "dev", "test", "staging",
    "portal", "vpn", "remote", "blog", "shop", "app", "cdn", "static",
    "docs", "support", "help", "status", "monitor", "git", "gitlab",
    "github", "jira", "confluence", "mx", "smtp", "pop", "imap",
    "webmail", "cpanel", "whm", "ns1", "ns2", "dns", "server",
    "host", "login", "secure", "auth", "sso", "beta", "v1", "v2"
]

found_subdomains = []
wildcard_ips = set()
lock = threading.Lock()


def get_wildcard_ips(domain: str) -> set:
    """Resolve a random nonexistent subdomain. If it resolves, the domain uses wildcard DNS."""
    rand = "".join(random.choices(string.ascii_lowercase, k=12))
    try:
        answers = dns.resolver.resolve(f"{rand}.{domain}", "A")
        return {str(r) for r in answers}
    except Exception:
        return set()


def resolve_subdomain(subdomain: str, domain: str):
    fqdn = f"{subdomain}.{domain}"
    try:
        answers = dns.resolver.resolve(fqdn, "A")
        ips = [str(r) for r in answers]

        if wildcard_ips and set(ips) == wildcard_ips:
            return  # wildcard fake hit

        with lock:
            found_subdomains.append({"subdomain": fqdn, "ips": ips})
            print(f"  [+] FOUND → {fqdn} : {', '.join(ips)}")
    except Exception:
        pass


def subdomain_enum(domain: str, wordlist: list = None, threads: int = 20) -> dict:
    global found_subdomains, wildcard_ips
    found_subdomains = []
    wildcard_ips = get_wildcard_ips(domain)

    wordlist = wordlist or DEFAULT_WORDLIST
    queue = Queue()
    for word in wordlist:
        queue.put(word)

    print(f"\n[*] Starting subdomain enum on: {domain}")
    print(f"[*] Wordlist size: {len(wordlist)} | Threads: {threads}")
    if wildcard_ips:
        print(f"[!] Wildcard DNS detected ({', '.join(wildcard_ips)}), filtering fake hits")
    print()

    def worker():
        while True:
            try:
                word = queue.get_nowait()
            except Exception:
                return
            resolve_subdomain(word, domain)
            queue.task_done()

    thread_list = []
    for _ in range(threads):
        t = threading.Thread(target=worker, daemon=True)
        t.start()
        thread_list.append(t)

    for t in thread_list:
        t.join()

    return {
        "status": "success",
        "domain": domain,
        "found": len(found_subdomains),
        "subdomains": found_subdomains,
        "wildcard": bool(wildcard_ips)
    }


def load_wordlist(filepath: str) -> list:
    try:
        with open(filepath, "r") as f:
            words = [line.strip() for line in f if line.strip()]
        print(f"[*] Loaded {len(words)} words from {filepath}")
        return words
    except FileNotFoundError:
        print(f"[!] Wordlist not found: {filepath}, using default")
        return DEFAULT_WORDLIST


def print_subdomain_results(result: dict):
    print("\n" + "=" * 40)
    print("  SUBDOMAIN ENUMERATION RESULTS")
    print("=" * 40)
    print(f"  Domain : {result['domain']}")
    print(f"  Found  : {result['found']} subdomains")
    print("-" * 40)
    for entry in result["subdomains"]:
        print(f"  {entry['subdomain']:<35} → {', '.join(entry['ips'])}")
    print("=" * 40 + "\n")


if __name__ == "__main__":
    domain = input("Enter target domain: ")

    print("1. Use built-in wordlist")
    print("2. Load custom wordlist file")
    choice = input("Choose: ")

    wordlist = load_wordlist(input("Wordlist path: ")) if choice == "2" else DEFAULT_WORDLIST
    print_subdomain_results(subdomain_enum(domain, wordlist))
