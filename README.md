# Recon Automation Script

A comprehensive, automated reconnaissance script for security testing and bug bounty hunting. Performs subdomain enumeration, live host detection, crawling, secret scanning, vulnerability recommendations, and more — all in one pass.

## Features

- **Single-pass httpx** — live host detection + tech stack detection combined (saves ~50% time)
- **Authenticated recon** — pass cookies to crawl behind login walls
- **Smart extractions** — automatically extracts API endpoints, admin panels, debug endpoints, secret files, and interesting parameters from crawl output
- **Nuclei recommendations** — analyzes recon data and suggests targeted nuclei commands (does not auto-run)
- **Performance caps** — auto-limits permutation count, JS input size, and crawl depth to prevent hangs
- **Proxy & rate limiting** — built-in support for Caido/Burp proxy and per-host rate limits
- **Resumable** — uses `.done` markers so interrupted runs pick up where they left off

## Requirements

Install these tools before running:

```bash
# Core tools
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install -v github.com/tomnomnom/assetfinder@latest
go install -v github.com/owasp-amass/amass/v4/...@master
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
go install -v github.com/tomnomnom/anew@latest
go install -v github.com/projectdiscovery/alterx/cmd/alterx@latest
go install -v github.com/d3mondev/puredns/v2@latest
go install -v github.com/projectdiscovery/chaos-client/cmd/chaos@latest
go install -v github.com/projectdiscovery/cdncheck/cmd/cdncheck@latest

# Optional (based on flags used)
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
go install -v github.com/projectdiscovery/katana/cmd/katana@latest
go install -v github.com/projectdiscovery/notify/cmd/notify@latest
go install -v github.com/rix4uni/mantra@latest
go install -v github.com/projectdiscovery/uncover/cmd/uncover@latest
```

Also required: `dig`, `whois`, `asnmap`, `puredns`

## Usage

```bash
chmod +x recon.sh
./recon.sh <target-domain> [OPTIONS]
```

### Options

| Flag | Description |
|------|-------------|
| `--help, -h` | Show help menu |
| `--skip-scope` | Skip scope broadening (ASN/whois) |
| `--skip-nuclei` | Skip Nuclei vulnerability scan |
| `--skip-jsleaks` | Skip Mantra JS secret scan |
| `--skip-katana` | Skip Katana crawl (JS, params extraction) |
| `--skip-permutations` | Skip subdomain permutations (alterx + puredns) |
| `--perms-limit <N>` | Max permutations to resolve (default: 50000) |
| `--cookie, -ck <str>` | Cookie for authenticated recon |
| `--proxy <url>` | Proxy URL (e.g., `http://localhost:8080`) |
| `--rate, -c <N>` | Requests per second |

### Examples

```bash
# Basic recon
./recon.sh example.com

# Skip nuclei and mantra, use proxy
./recon.sh example.com --skip-nuclei --skip-jsleaks --proxy http://localhost:8080

# Authenticated recon with rate limiting
./recon.sh example.com --cookie "session=abc123; token=xyz" -c 5

# Full recon with everything
./recon.sh example.com --cookie "session=abc123" --proxy http://127.0.0.1:8080 -c 10

# Skip permutations for faster run
./recon.sh example.com --skip-permutations
```

## How It Works

```
0. Scope Broadening
   └─ dig → IP resolution → asnmap → CIDR ranges → whois org info

1. Subdomain Enumeration (parallel)
   └─ subfinder + assetfinder + amass + chaos → subdomains.txt

2. Live Hosts + Tech Detection (single pass)
   └─ httpx -td → live_hosts.txt + tech_stack.txt

3. Katana Crawl
   └─ katana (depth 1, 200 pages/domain cap) → katana_urls.txt

3b. Smart Extractions from Katana
   ├─ all_js.txt           (JS files, deduped)
   ├─ api_endpoints.txt    (GraphQL, REST, versioned APIs)
   ├─ secret_files.txt     (.env, .git, .sql, .bak, keys)
   ├─ admin_panels.txt     (admin, dashboard, phpmyadmin)
   ├─ debug_endpoints.txt  (actuator, phpinfo, trace)
   ├─ interesting_params.txt (SSRF, redirect, IDOR params)
   └─ documents.txt        (PDF, CSV, XML, JSON)

4. Mantra JS Secret Scan
   └─ mantra (capped to 500 JS files, 20 threads)

4b. Nuclei Recommendations
   └─ Analyzes tech stack + extractions → recommends commands

5. Nuclei Vulnerability Scan
   └─ nuclei (with optional cookie/proxy/rate limit)

6. Subdomain Permutations
   └─ alterx (from live hosts, capped at 5000 input) → puredns resolve
```

## Output Structure

```
example.com/
├── subdomains.txt           # All discovered subdomains
├── live_hosts.txt           # Live HTTP/HTTPS hosts
├── tech_stack.txt           # Technology detection per host
├── katana_urls.txt          # All crawled URLs
├── all_js.txt               # Deduplicated JS files
├── jsfiles.txt              # JS files (copy of all_js.txt)
├── api_endpoints.txt        # API routes (/api/v1, /graphql, /swagger)
├── secret_files.txt         # Sensitive files (.env, .git, .sql, .bak)
├── admin_panels.txt         # Admin dashboards (/admin, /phpmyadmin)
├── debug_endpoints.txt      # Debug/health endpoints (/actuator, /trace)
├── interesting_params.txt   # URLs with vuln-prone params (?url=, ?id=, ?redirect=)
├── documents.txt            # Document files (PDF, CSV, XLSX)
├── katana_params.txt        # All URLs with query parameters
├── mantra_results.txt       # JS secret/API key findings
├── nuclei_results.txt       # Nuclei vulnerability findings
├── nuclei_recommendations.txt # Suggested nuclei commands
├── resolved_subs.txt        # Permutation-resolved subdomains
├── alterx_subs.txt          # Generated permutations
├── broad_scope.txt          # ASN/CIDR scope
├── cidr_ranges.txt          # Discovered CIDR ranges
├── ip_addrs.txt             # Resolved IP addresses
├── whois_info.txt           # WHOIS org info
└── .done/                   # Resumability markers
    ├── scope.done
    ├── subs.done
    ├── live.done
    ├── tech.done
    ├── katana.done
    ├── mantra.done
    ├── nuclei.done
    └── alterx.done
```

## Performance Optimizations

| Area | Optimization |
|------|-------------|
| **httpx** | Single pass for live detection + tech stack (was 2 passes) |
| **katana** | `-mdp 200` pages/domain cap, `-iqp` dedup, `-fsu` similar URL filter, `-hrl 10` per-host rate limit |
| **mantra** | JS input capped to 500 files, default 20 threads |
| **alterx** | Input capped to 5000 hosts if too large, uses live hosts instead of full subdomain list |
| **JS extraction** | Deduplicates by stripping query params before `sort -u` |
| **permutations** | Configurable `--perms-limit` (default 50k), auto-caps input |

## Authenticated Recon

Pass cookies to access pages behind login:

```bash
./recon.sh example.com --cookie "session=abc123; token=xyz"
```

This sends the cookie to:
- **httpx** — discovers auth-gated virtual hosts
- **katana** — crawls admin panels, dashboards, settings pages
- **mantra** — scans JS from authenticated areas (often contains more secrets)
- **nuclei** — tests authenticated endpoints

**Note:** Delete `.done` markers before re-running with cookies:
```bash
rm -rf example.com/.done
```

## Proxy Support

Route all traffic through Caido/Burp:

```bash
./recon.sh example.com --proxy http://localhost:8080
```

Works with: subfinder, httpx, katana, nuclei

## Resumability

The script uses `.done` marker files in `example.com/.done/`. If interrupted, re-run and it skips completed steps.

To force re-run a specific step:
```bash
rm example.com/.done/live.done    # re-run live detection
rm example.com/.done/katana.done  # re-run katana crawl
rm -rf example.com/.done          # re-run everything
```

## Disclaimer

This tool is for authorized security testing only. Always obtain proper authorization before running recon against any target. The author is not responsible for misuse of this tool.

## License

MIT
