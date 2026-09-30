import dns.resolver
import threading
from queue import Queue

# ── default wordlist (small built-in) ──────────────────────────────────────
DEFAULT_WORDLIST = [
    "www", "mail", "ftp", "admin", "api", "dev", "test", "staging",
    "portal", "vpn", "remote", "blog", "shop", "app", "cdn", "static",
    "docs", "support", "help", "status", "monitor", "git", "gitlab",
    "github", "jira", "confluence", "mx", "smtp", "pop", "imap",
    "webmail", "cpanel", "whm", "ns1", "ns2", "dns", "server",
    "host", "login", "secure", "auth", "sso", "beta", "v1", "v2"
]

found_subdomains = []   # shared list across threads
lock = threading.Lock() # thread-safe writes


def resolve_subdomain(subdomain: str, domain: str):
    """Try to resolve a subdomain. If it resolves → it exists."""
    fqdn = f"{subdomain}.{domain}"
    try:
        answers = dns.resolver.resolve(fqdn, "A")
        ips = [str(r) for r in answers]
        with lock:
            found_subdomains.append({"subdomain": fqdn, "ips": ips})
            print(f"  [+] FOUND → {fqdn} : {', '.join(ips)}")
    except Exception:
        pass  # subdomain doesn't exist, skip silently


def subdomain_enum(domain: str, wordlist: list = None, threads: int = 20) -> dict:
    """
    Enumerate subdomains using wordlist + threading.
    threads: number of concurrent threads (default 20)
    """
    global found_subdomains
    found_subdomains = []  # reset for each run

    wordlist = wordlist or DEFAULT_WORDLIST
    queue = Queue()

    # Fill queue with all words
    for word in wordlist:
        queue.put(word)

    print(f"\n[*] Starting subdomain enum on: {domain}")
    print(f"[*] Wordlist size: {len(wordlist)} | Threads: {threads}\n")

    def worker():
        while not queue.empty():
            word = queue.get()
            resolve_subdomain(word, domain)
            queue.task_done()

    # Spawn threads
    thread_list = []
    for _ in range(threads):
        t = threading.Thread(target=worker)
        t.daemon = True
        t.start()
        thread_list.append(t)

    # Wait for all threads to finish
    for t in thread_list:
        t.join()

    return {
        "status": "success",
        "domain": domain,
        "found": len(found_subdomains),
        "subdomains": found_subdomains
    }


def load_wordlist(filepath: str) -> list:
    """Load external wordlist file (one word per line)."""
    try:
        with open(filepath, "r") as f:
            words = [line.strip() for line in f if line.strip()]
        print(f"[*] Loaded {len(words)} words from {filepath}")
        return words
    except FileNotFoundError:
        print(f"[!] Wordlist not found: {filepath}, using default")
        return DEFAULT_WORDLIST


def print_subdomain_results(result: dict):
    print("\n" + "="*40)
    print("  SUBDOMAIN ENUMERATION RESULTS")
    print("="*40)
    print(f"  Domain : {result['domain']}")
    print(f"  Found  : {result['found']} subdomains")
    print("-"*40)
    for entry in result["subdomains"]:
        print(f"  {entry['subdomain']:<35} → {', '.join(entry['ips'])}")
    print("="*40 + "\n")


if __name__ == "__main__":
    domain = input("Enter target domain: ")

    print("1. Use built-in wordlist")
    print("2. Load custom wordlist file")
    choice = input("Choose: ")

    if choice == "2":
        path = input("Wordlist path: ")
        wordlist = load_wordlist(path)
    else:
        wordlist = DEFAULT_WORDLIST

    result = subdomain_enum(domain, wordlist)
    print_subdomain_results(result)
