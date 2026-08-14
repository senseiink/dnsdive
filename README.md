# SubSweep

A dependency-free subdomain enumerator written in pure Python. SubSweep combines wordlist brute-force with OSINT sources (certificate transparency and HackerTarget) to discover live subdomains of a target domain.

## Features

- Wordlist brute-force with a built-in list of 150 common names or your own custom wordlist
- OSINT enrichment from crt.sh (certificate transparency) and HackerTarget hostsearch
- Concurrent DNS resolution (A records) with configurable thread count
- Duplicate removal and filtering to the target domain
- Reports to terminal, or to text, CSV, or JSON files

## Requirements

- Python 3.8+

No external packages required.

## Usage

```
py subsweep.py <domain> [options]
```

### Examples

```bash
# Brute-force with the built-in wordlist plus OSINT sources
py subsweep.py example.com

# Use a custom wordlist
py subsweep.py example.com -w custom-wordlist.txt

# Increase concurrency and network timeout
py subsweep.py example.com -t 100 --timeout 3

# Save results to a text report
py subsweep.py example.com -o report.txt

# CSV report
py subsweep.py example.com -f csv -o report.csv

# Offline-only: disable OSINT lookups
py subsweep.py example.com --no-crtsh --no-hackertarget
```

### Options

| Option | Description |
| --- | --- |
| `domain` | The target domain, e.g. `example.com` |
| `-w, --wordlist` | Custom wordlist file (one word per line) |
| `-t, --threads` | Max concurrent DNS lookups (default: `50`) |
| `--timeout` | Network timeout in seconds (default: `5.0`) |
| `-f, --format` | Report format: `txt`, `csv`, or `json` (default: `txt`) |
| `-o, --output` | Save report to file |
| `--no-crtsh` | Disable certificate transparency lookup |
| `--no-hackertarget` | Disable HackerTarget lookup |
| `-V, --version` | Show version |

## How It Works

1. **Brute-force:** each word in the wordlist is combined with the domain and resolved concurrently using the system DNS resolver. Subdomains that resolve to at least one IPv4 address are kept.
2. **crt.sh:** queries the certificate transparency log for all certificates issued to `*.domain` and resolves the discovered names.
3. **HackerTarget:** queries the hostsearch API for DNS records associated with the domain.
4. Results are deduplicated, re-resolved, and reported.

## Sample Output

```
[*] Using built-in wordlist (150 entries)
[*] Brute-forcing 150 candidates ...
[*] Querying certificate transparency (crt.sh) ...
[*] Querying HackerTarget hostsearch ...
[+] api.example.com                         93.184.216.34
[+] www.example.com                         104.20.23.154, 172.66.147.243

========================================================
SubSweep completed
Resolving subdomains : 2
Elapsed time         : 6.29s
========================================================
```

## License

MIT License. See [LICENSE](LICENSE).

## Disclaimer

Use SubSweep only against domains you own or have explicit written permission to test. Unauthorized enumeration may be illegal in your jurisdiction and is against the terms of service of most networks. You are responsible for how you use this tool.
