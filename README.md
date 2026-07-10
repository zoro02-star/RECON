# Recon Automation Script

A comprehensive reconnaissance automation tool for security testing. Automates subdomain enumeration, live host detection, crawling, vulnerability scanning, and more.

## Features

- **Scope Broadening**: ASN/WHOIS discovery for target organization
- **Subdomain Enumeration**: Multi-source (subfinder, assetfinder, amass, chaos)
- **Live Host Detection**: httpx with tech stack detection
- **Deep Crawling**: Katana for JS, URLs, and parameter discovery
- **JS Secret Scanning**: Mantra for API key/secret detection
- **Vulnerability Scanning**: Nuclei templates
- **Subdomain Permutations**: alterx + puredns resolution
- **HTML Report**: Interactive dashboard with all findings
- **Resumable**: Skips completed steps on re-run

## Installation

### One-liner (recommended)

```bash
go install -v github.com/projectdiscovery/pdtm/cmd/pdtm@latest
pdtm -install

go install github.com/tomnomnom/anew@latest
go install github.com/d3mondev/puredns/v2@latest
go install github.com/owasp-amass/amass/v4/...@master
go install github.com/tomnomnom/assetfinder@latest

sudo apt install -y whois
```

### Individual Tool Installation

| Tool | Install Command |
|------|----------------|
| **subfinder** | `go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest` |
| **httpx** | `go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest` |
| **nuclei** | `go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest` |
| **katana** | `go install -v github.com/projectdiscovery/katana/cmd/katana@latest` |
| **amass** | `go install -v github.com/owasp-amass/amass/v4/...@master` |
| **assetfinder** | `go install github.com/tomnomnom/assetfinder@latest` |
| **anew** | `go install github.com/tomnomnom/anew@latest` |
| **alterx** | `go install -v github.com/projectdiscovery/alterx/cmd/alterx@latest` |
| **puredns** | `go install github.com/d3mondev/puredns/v2@latest` |
| **chaos** | `go install -v github.com/projectdiscovery/chaos-client/cmd/chaos@latest` |
| **asnmap** | `go install -v github.com/projectdiscovery/asnmap/cmd/asnmap@latest` |
| **notify** | `go install -v github.com/projectdiscovery/notify/cmd/notify@latest` |

### Post-Install

```bash
nuclei -update-templates
```

### API Keys (optional)

```bash
# Chaos API key (free at https://projectdiscovery.io)
export CHAOS_API_KEY="your-key-here"
echo 'export CHAOS_API_KEY="your-key-here"' >> ~/.bashrc
```

### Verify Installation

```bash
subfinder -version && httpx -version && nuclei -version && katana -version
```

## Usage

```bash
./recon.sh example.com
./recon.sh example.com --skip-nuclei --skip-jsleaks
./recon.sh example.com --proxy http://localhost:8080
./recon.sh example.com -c 5
./recon.sh example.com --proxy http://127.0.0.1:8080 --skip-nuclei -c 10
```

## Options

| Option | Description |
|--------|-------------|
| `--help, -h` | Show help menu |
| `--skip-scope` | Skip scope broadening (ASN/whois) |
| `--skip-nuclei` | Skip Nuclei vulnerability scan |
| `--skip-jsleaks` | Skip Mantra JS secret scan |
| `--skip-katana` | Skip Katana crawl |
| `--proxy <url>` | Proxy URL (e.g., http://localhost:8080) |
| `--rate, -c <n>` | Requests per second |

## Output Structure

```
target-domain.com/
├── subdomains.txt          # All discovered subdomains
├── live_hosts.txt          # Live HTTP/HTTPS hosts
├── tech_stack.txt          # Technology detection
├── broad_scope.txt         # ASN/CIDR ranges
├── cidr_ranges.txt         # Discovered CIDR blocks
├── ip_addrs.txt            # Resolved IP addresses
├── katana_urls.txt         # Crawled URLs
├── katana_params.txt       # URLs with query parameters
├── all_js.txt              # JavaScript files
├── jsfiles.txt             # JS files (filtered)
├── mantra_results.txt      # API key/secret findings
├── nuclei_results.txt      # Vulnerability findings
├── alterx_subs.txt         # Generated permutations
├── resolved_subs.txt       # Resolved permutation subs
├── whois_info.txt          # WHOIS data
└── report.html             # Interactive HTML report
```

## How It Works

1. **Scope Broadening**: Resolves domain IPs, discovers ASN/CIDR ranges
2. **Subdomain Enumeration**: Runs subfinder, assetfinder, amass, chaos in parallel
3. **Live Host Detection**: Probes subdomains with httpx
4. **Tech Stack**: Identifies technologies on live hosts
5. **Katana Crawl**: Deep crawl for URLs, JS files, parameters
6. **Mantra Scan**: Scans JS files for leaked API keys
7. **Nuclei Scan**: Runs vulnerability templates against live hosts
8. **Permutations**: Generates and resolves subdomain variations
9. **Report**: Generates interactive HTML dashboard

## Requirements

- Go 1.21+
- Bash 4+
- System: `dig`, `whois` (pre-installed on Kali)

## License

For authorized security testing only.