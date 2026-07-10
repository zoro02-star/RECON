# recon.sh — Automated Recon Pipeline

Multi-stage reconnaissance automation for security testing. Results saved to `./<domain>/` with an HTML report.

## Pipeline

| Step | Tool(s) | Output |
|---|---|---|
| 0 | Scope Broadening | `dig`, `asnmap`, `whois` | CIDR ranges, org info |
| 1 | Subdomain Enumeration | `subfinder`, `assetfinder`, `amass`, `chaos` | `subdomains.txt` |
| 2 | Live Host Detection | `httpx` (50 threads) | `live_hosts.txt` |
| 2b | Tech Stack Detection | `httpx -td` | `tech_stack.txt` |
| 3 | Deep Crawl | `katana` (depth 2, max 500 p/host) | `katana_urls.txt`, `all_js.txt`, `katana_params.txt` |
| 4 | JS Secret Scanning | `mantra` | `mantra_results.txt` |
| 5 | Port Scanning | `naabu` (top 1000, SYN, 5000 pps) | `ports.txt` |
| 6 | Vulnerability Scan | `nuclei` | `nuclei_results.txt` |
| 7 | Permutations | `alterx` + `puredns` | `resolved_subs.txt` |

## Usage

```bash
./recon.sh example.com
./recon.sh example.com --proxy http://127.0.0.1:8080 -c 10
./recon.sh example.com --skip-nuclei --skip-jsleaks
```

## Options

| Flag | Description |
|---|---|
| `--skip-scope` | Skip ASN/whois discovery |
| `--skip-nuclei` | Skip vulnerability scan |
| `--skip-jsleaks` | Skip Mantra JS scanning |
| `--skip-portscan` | Skip naabu port scan |
| `--skip-katana` | Skip katana crawl |
| `--proxy` | HTTP proxy (e.g., `http://localhost:8080`) |
| `--rate, -c` | Requests per second (default varies by tool) |

## Checkpointing

Completed steps are tracked via `.done` marker files in `<domain>/.done/`. Interrupted runs resume from where they left off — already-finished steps are skipped.

## OOM Protection

Virtual memory is capped at 6 GB via `ulimit` to prevent the system from locking up during resource-heavy stages (katana, nuclei).

## Output Structure

```
<domain>/
├── subdomains.txt
├── live_hosts.txt
├── tech_stack.txt
├── katana_urls.txt
├── katana_params.txt
├── all_js.txt / jsfiles.txt
├── mantra_results.txt
├── ports.txt
├── nuclei_results.txt
├── resolved_subs.txt
├── cidr_ranges.txt / ip_addrs.txt / broad_scope.txt
├── whois_info.txt
├── report.html
└── .done/
```

## Requirements

`subfinder`, `assetfinder`, `amass`, `httpx`, `naabu`, `nuclei`, `anew`, `katana`, `notify`, `mantra`, `alterx`, `puredns`, `chaos`, `asnmap`
