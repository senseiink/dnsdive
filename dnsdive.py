#!/usr/bin/env python3
"""DnsDive - a dependency-free subdomain enumerator using wordlist brute-force and OSINT sources."""

import argparse
import csv
import json
import os
import socket
import sys
import time
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime

VERSION = "1.0.0"

DEFAULT_WORDLIST = [
    "www", "www2", "web", "api", "app", "apps", "admin", "administrator", "auth",
    "account", "accounts", "portal", "mail", "mx", "smtp", "pop", "imap", "webmail",
    "ns1", "ns2", "ns3", "dns", "vpn", "remote", "secure", "ssl", "ftp", "sftp",
    "ssh", "dev", "development", "staging", "stage", "test", "testing", "qa",
    "demo", "beta", "alpha", "preview", "blog", "support", "help", "status",
    "docs", "documentation", "wiki", "kb", "forum", "community", "news", "media",
    "cdn", "static", "assets", "images", "img", "download", "downloads", "files",
    "file", "upload", "uploads", "store", "shop", "checkout", "payment", "billing",
    "gateway", "pay", "login", "signin", "signup", "register", "member", "members",
    "user", "users", "client", "clients", "customer", "customers", "partners",
    "partner", "affiliate", "affiliates", "mailer", "list", "lists", "newsletter",
    "tracking", "tracker", "analytics", "metrics", "stats", "monitor", "monitoring",
    "logs", "log", "graphql", "api-dev", "api-staging", "api-test", "m", "mobile",
    "mob", "shop", "store", "shopify", "cart", "orders", "order", "search",
    "devops", "jenkins", "gitlab", "git", "github", "ci", "cd", "build", "jenkins",
    "jira", "confluence", "grafana", "kibana", "elastic", "elasticsearch", "database",
    "db", "mysql", "postgres", "redis", "mongo", "mongodb", "docker", "registry",
    "k8s", "kubernetes", "storage", "backup", "backups", "archives", "internal",
    "intranet", "office", "corp", "corporate", "hr", "finance", "erp", "crm", "cms",
]

DEFAULT_THREADS = 50
DEFAULT_TIMEOUT = 5.0


def resolve_a(host, timeout):
    try:
        infos = socket.getaddrinfo(host, None, socket.AF_INET, socket.SOCK_STREAM)
        return sorted({info[4][0] for info in infos})
    except socket.gaierror:
        return []


def sanitize_name(name):
    name = name.strip().lower()
    if name.startswith("*."):
        name = name[2:]
    return name.rstrip(".")


def is_related(name, domain):
    return name == domain or name.endswith("." + domain)


def fetch_url(url, timeout):
    req = urllib.request.Request(url, headers={"User-Agent": "DnsDive/%s" % VERSION})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return resp.read().decode("utf-8", errors="replace")


def from_crtsh(domain, timeout):
    url = "https://crt.sh/?q=%%25.%s&output=json" % domain
    try:
        raw = fetch_url(url, timeout)
    except (urllib.error.URLError, urllib.error.HTTPError, socket.timeout, ValueError):
        return []
    try:
        entries = json.loads(raw)
    except json.JSONDecodeError:
        return []
    names = set()
    for entry in entries:
        for key in ("name_value", "name"):
            value = entry.get(key)
            if not value:
                continue
            for name in value.split("\n"):
                name = sanitize_name(name)
                if name and is_related(name, domain):
                    names.add(name)
    return sorted(names)


def from_hackertarget(domain, timeout):
    url = "https://api.hackertarget.com/hostsearch/?q=%s" % domain
    try:
        raw = fetch_url(url, timeout)
    except (urllib.error.URLError, urllib.error.HTTPError, socket.timeout, ValueError):
        return []
    names = set()
    for line in raw.splitlines():
        if "," not in line or "API count exceeded" in line:
            continue
        name = sanitize_name(line.split(",")[0])
        if name and is_related(name, domain):
            names.add(name)
    return sorted(names)


def brute_force(domain, wordlist, threads, timeout):
    def try_name(word):
        candidate = "%s.%s" % (word, domain)
        return candidate, resolve_a(candidate, timeout)

    found = {}
    with ThreadPoolExecutor(max_workers=threads) as pool:
        futures = {pool.submit(try_name, word): word for word in wordlist}
        for future in as_completed(futures):
            candidate, ips = future.result()
            if ips:
                found[candidate] = ips
    return found


def write_txt(domain, found, started, elapsed):
    lines = [
        "=" * 56,
        "DnsDive Report",
        "Domain: %s" % domain,
        "Generated: %s" % started.strftime("%Y-%m-%d %H:%M:%S"),
        "Resolving subdomains: %d" % len(found),
        "Elapsed: %.2fs" % elapsed,
        "=" * 56,
    ]
    for name in sorted(found):
        lines.append("%-40s %s" % (name, ", ".join(found[name])))
    lines.append("=" * 56)
    return "\n".join(lines)


def write_csv(domain, found, started, elapsed):
    output = []
    for name in sorted(found):
        output.append({"domain": domain, "subdomain": name, "ip": ", ".join(found[name])})
    return output


def save_output(text, output):
    if not output:
        return None
    os.makedirs(os.path.dirname(os.path.abspath(output)), exist_ok=True)
    with open(output, "w", encoding="utf-8") as f:
        f.write(text)
    return output


def load_wordlist(path):
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        words = [line.strip().lower() for line in f if line.strip()]
    if not words:
        sys.exit("error: wordlist is empty")
    return words


def build_parser():
    parser = argparse.ArgumentParser(
        prog="dnsdive",
        description="Dependency-free subdomain enumerator using wordlist brute-force and OSINT sources.",
        epilog="examples:\n"
        "  py dnsdive.py example.com\n"
        "  py dnsdive.py example.com -w custom-wordlist.txt\n"
        "  py dnsdive.py example.com -t 100 --timeout 3 -o report.txt\n"
        "  py dnsdive.py example.com -f csv -o report.csv\n"
        "  py dnsdive.py example.com --no-crtsh --no-hackertarget",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("domain", help="the target domain, e.g. example.com")
    parser.add_argument("-w", "--wordlist", help="custom wordlist file (one word per line)")
    parser.add_argument("-t", "--threads", type=int, default=DEFAULT_THREADS,
                        help="max concurrent DNS lookups (default: %d)" % DEFAULT_THREADS)
    parser.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT,
                        help="network timeout in seconds (default: %s)" % DEFAULT_TIMEOUT)
    parser.add_argument("-f", "--format", choices=["txt", "csv", "json"], default="txt",
                        help="report format (default: txt)")
    parser.add_argument("-o", "--output", help="save report to this file")
    parser.add_argument("--no-crtsh", action="store_true", help="disable certificate transparency lookup")
    parser.add_argument("--no-hackertarget", action="store_true", help="disable HackerTarget lookup")
    parser.add_argument("-V", "--version", action="version", version="%(prog)s " + VERSION)
    return parser


def main():
    parser = build_parser()
    args = parser.parse_args()

    domain = args.domain.strip().lower().rstrip(".")
    if not domain or "." not in domain:
        parser.error("invalid domain: %s" % args.domain)

    started = datetime.now()
    start_time = time.time()

    if args.wordlist:
        words = load_wordlist(args.wordlist)
        print("[*] Using wordlist: %s (%d entries)" % (args.wordlist, len(words)))
    else:
        words = sorted(set(DEFAULT_WORDLIST))
        print("[*] Using built-in wordlist (%d entries)" % len(words))

    found = {}

    print("[*] Brute-forcing %d candidates ..." % len(words))
    found.update(brute_force(domain, words, args.threads, args.timeout))

    if not args.no_crtsh:
        print("[*] Querying certificate transparency (crt.sh) ...")
        for name in from_crtsh(domain, args.timeout):
            ips = resolve_a(name, args.timeout)
            if ips:
                found[name] = ips

    if not args.no_hackertarget:
        print("[*] Querying HackerTarget hostsearch ...")
        for name in from_hackertarget(domain, args.timeout):
            ips = resolve_a(name, args.timeout)
            if ips:
                found[name] = ips

    elapsed = time.time() - start_time

    if args.format == "csv":
        rows = write_csv(domain, found, started, elapsed)
        report_text = ""
        if args.output:
            with open(args.output, "w", encoding="utf-8", newline="") as f:
                writer = csv.DictWriter(f, fieldnames=["domain", "subdomain", "ip"])
                writer.writeheader()
                writer.writerows(rows)
    elif args.format == "json":
        payload = {
            "tool": "dnsdive",
            "version": VERSION,
            "domain": domain,
            "started": started.isoformat(timespec="seconds"),
            "elapsed_seconds": round(elapsed, 2),
            "subdomains": {name: found[name] for name in sorted(found)},
        }
        report_text = json.dumps(payload, indent=2)
        if args.output:
            save_output(report_text, args.output)
    else:
        report_text = write_txt(domain, found, started, elapsed)
        if args.output:
            save_output(report_text, args.output)

    for name in sorted(found):
        print("[+] %-40s %s" % (name, ", ".join(found[name])))

    print("\n" + "=" * 56)
    print("DnsDive completed")
    print("Resolving subdomains : %d" % len(found))
    print("Elapsed time         : %.2fs" % elapsed)
    if args.output:
        print("Report saved         : %s" % args.output)
    print("=" * 56)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nInterrupted by user.")
        sys.exit(130)
    except ValueError as exc:
        sys.exit("error: %s" % exc)
