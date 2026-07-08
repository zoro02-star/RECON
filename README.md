# Recon Automation Script

Automated reconnaissance pipeline for security testing and bug bounty hunting. Runs 10+ industry-standard tools in sequence to discover subdomains, live hosts, tech stacks, JS files, secrets, open ports, screenshots, XSS vulnerabilities, and more.

## Pipeline

```
[0] Scope Broadening  ─── dig → asnmap → whois
       │
[1] Subdomain Enum.  ─── subfinder + assetfinder + amass + chaos
       │
[2] Live Hosts       ─── httpx
       │
[2b] Tech Stack      ─── httpx -td
       │
[3] Katana Crawl     ─── katana (depth 3, JS, params)
       │
[4] Mantra Secrets   ─── mantra (JS leak scan)
       │
[5] Port Scan        ─── naabu (SYN, top 1000)
       │
[5b] Screenshots     ─── gowitness
       │
[5c] XSS Scan        ─── waybackurls → gf xss → dalfox
       │
[6] Nuclei Scan      ─── nuclei (vulnerability scanner)
       │
[7] Permutations     ─── alterx → puredns
       │
       ▼
   HTML Report + Summary
```

## Traffic Per Tool

Each tool generates HTTP/DNS traffic. This chart shows approximate requests sent to the target domain per tool:

```
Tool               Requests     Bandwidth     Notes
─────────────────────────────────────────────────────────
scope (dig)            2-5        ~1 KB       DNS lookups
asnmap                 1-3        ~1 KB       ASN queries
whois                  1          ~1 KB       WHOIS query
subfinder            50-500      ~50-500 KB   DNS + API calls
assetfinder           10-50      ~10-50 KB    API to crt.sh
amass                100-500     ~100-500 KB  Passive DNS + APIs
chaos                 10-50      ~10-50 KB    Chaos DB API
httpx (live)        N_subdomains  ~1-5 KB/host HTTP probes
httpx (tech)        N_live         ~2-5 KB/host HTTP + response
katana              N_live × 3-50  ~10-500 KB Crawl depth 3
mantra               N_js_files    ~1-10 KB/file  JS fetch
naabu               N_ports × N_hosts  packet-level SYN scan
gowitness           N_ports       ~200-500 KB/screenshot
waybackurls             1          ~10-50 KB  Wayback CDX API
dalfox              N_xss_urls × payloads  ~1-10 KB/url
nuclei              N_templates × N_hosts  ~1-5 KB/template
alterx + puredns    N_permutations  DNS resolution
```

### Relative Traffic Volume

```
Request Volume (approximate, log scale)

scope         ░
subfinder     ████████░░░░░░░░░░░░
assetfinder   ███░░░░░░░░░░░░░░░░░
amass         █████████░░░░░░░░░░░
chaos         ██░░░░░░░░░░░░░░░░░░
httpx         █████░░░░░░░░░░░░░░░
katana        ██████████████░░░░░░
mantra        ██░░░░░░░░░░░░░░░░░░
naabu         ████████████████████  (packet-level, most traffic)
gowitness     █████░░░░░░░░░░░░░░░
waybackurls   █░░░░░░░░░░░░░░░░░░░
dalfox        ███████░░░░░░░░░░░░░
nuclei        ████████████████████  (many templates per host)
alterx/puredns █████░░░░░░░░░░░░░░
```

## Requirements

| Tool | Install |
|------|---------|
| subfinder | `go install github.com/projectdiscovery/subfinder/v2@latest` |
| assetfinder | `go install github.com/tomnomnom/assetfinder@latest` |
| amass | `go install github.com/owasp-amass/amass/v3@latest` |
| httpx | `go install github.com/projectdiscovery/httpx@latest` |
| naabu | `go install github.com/projectdiscovery/naabu/v2@latest` |
| nuclei | `go install github.com/projectdiscovery/nuclei/v3@latest` |
| katana | `go install github.com/projectdiscovery/katana@latest` |
| chaos | `go install github.com/projectdiscovery/chaos-client/cmd/chaos@latest` |
| notify | `go install github.com/projectdiscovery/notify/cmd/notify@latest` |
| gowitness | `go install github.com/sensepost/gowitness@latest` |
| dalfox | `go install github.com/hahwul/dalfox/v2@latest` |
| asnmap | `go install github.com/projectdiscovery/asnmap/cmd/asnmap@latest` |
| waybackurls | `go install github.com/tomnomnom/waybackurls@latest` |
| gf | `go install github.com/tomnomnom/gf@latest` |
| qsreplace | `go install github.com/tomnomnom/qsreplace@latest` |
| mantra | `go install github.com/MrEmpy/mantra@latest` |
| alterx | `go install github.com/projectdiscovery/alterx@latest` |
| puredns | `go install github.com/d3mondev/puredns/v2@latest` |
| anew | `go install github.com/tomnomnom/anew@latest` |

Also requires: `dig`, `whois`, `curl` (standard Linux tools)

## Usage

```bash
./recon.sh example.com
./recon.sh example.com --skip-nuclei --skip-jsleaks
./recon.sh example.com --proxy http://127.0.0.1:8080 -c 10
```

### Skip Flags

| Flag | Skips |
|------|-------|
| `--skip-scope` | Scope broadening (ASN/whois) |
| `--skip-nuclei` | Nuclei vulnerability scan |
| `--skip-jsleaks` | Mantra JS secret scan |
| `--skip-portscan` | Naabu port scan |
| `--skip-screenshots` | Gowitness screenshots |
| `--skip-xss` | Dalfox XSS scan |
| `--skip-katana` | Katana crawl |
| `--proxy` | HTTP/SOCKS5 proxy for all tools |
| `--rate, -c` | Requests per second limit |

## Output Structure

```
example.com/
├── subdomains.txt          # All discovered subdomains
├── live_hosts.txt          # Live HTTP/HTTPS hosts
├── tech_stack.txt          # Technology stack per host
├── katana_urls.txt         # Crawled URLs
├── katana_params.txt       # URLs with parameters
├── jsfiles.txt / all_js.txt  # JavaScript files
├── mantra_results.txt      # Secrets/keys found
├── ports.txt               # Open ports (host:port)
├── screenshots/            # Web page screenshots
├── xss_results.txt         # XSS vulnerabilities
├── nuclei_results.txt      # Vulnerability findings
├── resolved_subs.txt       # Resolved permutations
├── broad_scope.txt         # Discovered CIDR ranges
├── cidr_ranges.txt         # ASN CIDR ranges
├── ip_addrs.txt            # Resolved IP addresses
├── whois_info.txt          # Whois organization info
├── screenshots.jsonl       # Gowitness metadata
└── report.html             # Dark-themed HTML report
```

## Notes

- All sections are idempotent (skip if output exists)
- Use `--skip-*` flags to disable slow/noisy sections
- Proxy support via `--proxy` (SOCKS5/HTTP)
- HTML report includes search, filtering, collapsible sections
- Screenshots require Chrome (auto-downloaded by gowitness on first run)
