#!/usr/bin/env bash

set -euo pipefail

############################
# Colors
############################
RED="\033[0;31m"
GREEN="\033[0;32m"
YELLOW="\033[1;33m"
BLUE="\033[0;34m"
NC="\033[0m"

############################
# Ctrl+C Handler
############################
trap 'echo -e "\n${RED}[!] Interrupted. Exiting...${NC}"; exit 1' INT

############################
# Help Menu
############################
show_help() {
  cat <<EOF
${BLUE}Recon Automation Script${NC}
A comprehensive reconnaissance automation tool for security testing.

${YELLOW}USAGE:${NC}
  $0 <target-domain> [OPTIONS]

${YELLOW}OPTIONS:${NC}
   --help, -h              Show this help menu
  --skip-scope            Skip scope broadening (ASN/whois)
  --skip-nuclei           Skip Nuclei vulnerability scan
  --skip-jsleaks          Skip Mantra JS secret scan
  --skip-portscan         Skip naabu port scan
  --skip-screenshots      Skip gowitness screenshots
  --skip-xss              Skip dalfox XSS scan
  --skip-katana           Skip Katana crawl (JS, params extraction)
  --proxy                 Proxy URL (e.g., http://localhost:8080 for Caido)
  --rate, -c             Requests per second (e.g., -c 5 for 5 req/sec)

${YELLOW}EXAMPLES:${NC}
  $0 example.com
  $0 example.com --skip-nuclei --skip-jsleaks
  $0 example.com --proxy http://localhost:8080
  $0 example.com --proxy http://127.0.0.1:8080 --skip-nuclei
  $0 example.com -c 5
  $0 example.com -c 10 --proxy http://localhost:8080

${YELLOW}DESCRIPTION:${NC}
  This script automates the reconnaissance process for a given target domain.
  It performs the following steps in order:
    0. Scope Broadening (ASN/whois discovery)
    1. Subdomain Enumeration (subfinder, assetfinder, amass, chaos)
    2. Live Host Detection (httpx)
    3. Katana Crawl (deep URL/JS/params discovery)
     4. Mantra JS Secret Scan (API key leak detection)
     5. Port Scanning (naabu)
     5b. Screenshots (gowitness)
     5c. XSS Scanning (dalfox)
     6. Vulnerability Scanning (nuclei)
     7. Subdomain Permutations (alterx + puredns)
  All results are saved in a directory named after the target domain.
  Skipped steps will not be executed, and their output files will not be created.

${BLUE}Author: Recon Automation${NC}
EOF
  exit 0
}

############################
# Parse Arguments
############################
SKIP_NUCLEI=false
SKIP_JSLEAKS=false
SKIP_SCOPE=false
SKIP_PORTSCAN=false
SKIP_SCREENSHOTS=false
SKIP_XSS=false
SKIP_KATANA=false
PROXY=""
RATE=""

# First non-flag argument must be the domain
if [ $# -lt 1 ]; then
  echo -e "${YELLOW}Usage: $0 target-domain.com [OPTIONS]${NC}"
  echo -e "${YELLOW}Run '$0 --help' for more information.${NC}"
  exit 1
fi

if [[ "$1" == "--help" ]] || [[ "$1" == "-h" ]]; then
  show_help
fi

domain=$1
shift

while [[ $# -gt 0 ]]; do
  case "$1" in
    --help|-h)
      show_help
      ;;
    --skip-nuclei)
      SKIP_NUCLEI=true
      ;;
    --skip-jsleaks)
      SKIP_JSLEAKS=true
      ;;
    --skip-scope)
      SKIP_SCOPE=true
      ;;
    --skip-portscan)
      SKIP_PORTSCAN=true
      ;;
    --skip-screenshots)
      SKIP_SCREENSHOTS=true
      ;;
    --skip-xss)
      SKIP_XSS=true
      ;;
    --skip-katana)
      SKIP_KATANA=true
      ;;
    --proxy)
      PROXY="$2"
      shift
      ;;
    --rate|-c)
      RATE="$2"
      shift
      ;;
    *)
      echo -e "${RED}[!] Unknown option: $1${NC}"
      echo -e "${YELLOW}Run '$0 --help' for more information.${NC}"
      exit 1
      ;;
  esac
  shift
done

if [ -n "$PROXY" ]; then
  echo -e "${BLUE}[*] Using proxy: $PROXY${NC}"
fi

if [ -n "$RATE" ]; then
  echo -e "${BLUE}[*] Rate limit: $RATE req/sec${NC}"
fi

############################
# Check Target
############################
outdir=$domain

mkdir -p "$outdir"

############################
# Required Tools
############################
tools=(subfinder assetfinder amass httpx naabu nuclei anew katana notify mantra alterx puredns chaos gowitness dalfox asnmap waybackurls gf qsreplace)

for tool in "${tools[@]}"; do
  if ! command -v "$tool" &>/dev/null; then
    echo -e "${RED}[!] $tool not found. Install it first.${NC}"
    exit 1
  fi
done

############################
# Files
############################
subs="$outdir/subdomains.txt"
live="$(pwd)/$outdir/live_hosts.txt"
tech_file="$outdir/tech_stack.txt"
js="$outdir/jsfiles.txt"
ports="$outdir/ports.txt"
nuclei_out="$outdir/nuclei_results.txt"
mantra_out="$outdir/mantra_results.txt"
resolved="$outdir/resolved_subs.txt"
scope_file="$outdir/broad_scope.txt"
cidr_file="$outdir/cidr_ranges.txt"
ip_file="$outdir/ip_addrs.txt"

############################
# 0. Scope Broadening
############################
if [ "$SKIP_SCOPE" = false ]; then
  if [ ! -f "$scope_file" ]; then
    echo -e "${BLUE}[*] Broadening scope for $domain${NC}"
    touch "$scope_file"

    # Resolve domain to IPs
    echo -e "${YELLOW}[*] Resolving domain IPs${NC}"
    dig +short "$domain" | grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$' > "$ip_file" || true
    echo -e "${GREEN}[+] Resolved $(wc -l <"$ip_file") IPs${NC}"

    # ASN discovery via asnmap
    if [ -s "$ip_file" ]; then
      echo -e "${YELLOW}[*] Discovering ASN and CIDR ranges${NC}"
      head -1 "$ip_file" | asnmap -i - -silent | anew "$cidr_file" || true
      if [ -s "$cidr_file" ]; then
        echo -e "${GREEN}[+] Found $(wc -l <"$cidr_file") CIDR ranges${NC}"
        cat "$cidr_file" >> "$scope_file"
      else
        asnmap -d "$domain" -silent | anew "$cidr_file" || true
        if [ -s "$cidr_file" ]; then
          echo -e "${GREEN}[+] Found $(wc -l <"$cidr_file") CIDR ranges${NC}"
          cat "$cidr_file" >> "$scope_file"
        fi
      fi
    fi

    # Whois org discovery
    echo -e "${YELLOW}[*] Running whois lookup${NC}"
    whois "$domain" 2>/dev/null | grep -iE "OrgName|OrgId|Organization|descr:" | head -5 | sed 's/^[[:space:]]*//' | anew "$outdir/whois_info.txt" || true
    echo -e "${GREEN}[+] Whois info saved${NC}"

    echo -e "${BLUE}[*] Scope broadening complete. Saved to $scope_file${NC}"
  fi
else
  echo -e "${YELLOW}[*] Skipping scope broadening${NC}"
fi

############################
# 1. Subdomain Enumeration
############################
if [ ! -f "$subs" ]; then
  echo -e "${BLUE}[*] Running subdomain enumeration${NC}"
  (
    if [ -n "$PROXY" ] && [ -n "$RATE" ]; then
      subfinder -d "$domain" -silent -rl "$RATE" -proxy "$PROXY" &
      assetfinder --subs-only "$domain" &
      amass enum -passive -d "$domain" -dns-qps "$RATE" 2>/dev/null &
      chaos -d "$domain" -silent 2>/dev/null || true
    elif [ -n "$PROXY" ]; then
      subfinder -d "$domain" -silent -proxy "$PROXY" &
      assetfinder --subs-only "$domain" &
      amass enum -passive -d "$domain" 2>/dev/null &
      chaos -d "$domain" -silent 2>/dev/null || true
    elif [ -n "$RATE" ]; then
      subfinder -d "$domain" -silent -rl "$RATE" &
      assetfinder --subs-only "$domain" &
      amass enum -passive -d "$domain" -dns-qps "$RATE" 2>/dev/null &
      chaos -d "$domain" -silent 2>/dev/null || true
    else
      subfinder -d "$domain" -silent &
      assetfinder --subs-only "$domain" &
      amass enum -passive -d "$domain" 2>/dev/null &
      chaos -d "$domain" -silent 2>/dev/null || true
    fi
    wait
  ) | anew "$subs"
  echo -e "${GREEN}[+] Found $(wc -l <"$subs") subdomains${NC}"
fi

############################
# 2. Live Hosts
############################
if [ ! -f "$live" ]; then
  echo -e "${BLUE}[*] Checking live hosts${NC}"
  if [ -n "$PROXY" ] && [ -n "$RATE" ]; then
    cat "$subs" | httpx -silent -threads 100 -rl "$RATE" -proxy "$PROXY" | anew "$live"
  elif [ -n "$PROXY" ]; then
    cat "$subs" | httpx -silent -threads 100 -proxy "$PROXY" | anew "$live"
  elif [ -n "$RATE" ]; then
    cat "$subs" | httpx -silent -threads 100 -rl "$RATE" | anew "$live"
  else
    cat "$subs" | httpx -silent -threads 100 | anew "$live"
  fi
  echo -e "${GREEN}[+] Live hosts: $(wc -l <"$live")${NC}"
fi

############################
# 2b. Tech Stack Detection
############################
if [ ! -f "$tech_file" ]; then
  echo -e "${BLUE}[*] Detecting technology stacks${NC}"
  if [ -f "$live" ] && [ -s "$live" ]; then
    cat "$live" | httpx -silent -td 2>/dev/null | sed 's/\x1b\[[0-9;]*m//g' | sed 's/^\(https\?:\/\/[^ ]*\) \[\(.*\)\]$/\1: \2/' > "$tech_file" || true
    echo -e "${GREEN}[+] Tech stack detected for $(wc -l <"$tech_file") hosts${NC}"
  else
    echo -e "${YELLOW}[!] No live hosts to scan for tech${NC}"
    touch "$tech_file"
  fi
fi

############################
# 3. Katana Crawl
############################
if [ "$SKIP_KATANA" = false ]; then
  js="$outdir/jsfiles.txt"
  js_all="$outdir/all_js.txt"

  if [ ! -f "$js_all" ]; then
    echo -e "${BLUE}[*] Running katana crawl for URLs, params, and JS files${NC}"
    if [ -n "$PROXY" ] && [ -n "$RATE" ]; then
      katana -list "$live" -d 3 -jc -jsluice -ef woff,css,svg,png,jpg,gif -silent -rl "$RATE" -proxy "$PROXY" | anew "$outdir/katana_urls.txt"
    elif [ -n "$PROXY" ]; then
      katana -list "$live" -d 3 -jc -jsluice -ef woff,css,svg,png,jpg,gif -silent -proxy "$PROXY" | anew "$outdir/katana_urls.txt"
    elif [ -n "$RATE" ]; then
      katana -list "$live" -d 3 -jc -jsluice -ef woff,css,svg,png,jpg,gif -silent -rl "$RATE" | anew "$outdir/katana_urls.txt"
    else
      katana -list "$live" -d 3 -jc -jsluice -ef woff,css,svg,png,jpg,gif -silent | anew "$outdir/katana_urls.txt"
    fi

    echo -e "${YELLOW}[*] Extracting JS files from katana crawl${NC}"
    grep -E ".*\.js($|\\?.*)" "$outdir/katana_urls.txt" | anew "$js_all" || true
    cp "$js_all" "$js" 2>/dev/null || true

    echo -e "${YELLOW}[*] Extracting URLs with query parameters from katana${NC}"
    grep "=" "$outdir/katana_urls.txt" | anew "$outdir/katana_params.txt" || true

    echo -e "${GREEN}[+] Katana URLs: $(wc -l <"$outdir/katana_urls.txt" 2>/dev/null || echo 0)${NC}"
    echo -e "${GREEN}[+] Total JS files: $(wc -l <"$js_all" 2>/dev/null || echo 0)${NC}"
  fi
else
  echo -e "${YELLOW}[*] Skipping Katana crawl and related extractions${NC}"
  js="$outdir/jsfiles.txt"
  js_all="$outdir/all_js.txt"
fi

############################
# 4. Mantra JS Secret Scan
############################
if [ "$SKIP_JSLEAKS" = false ]; then
  js_scan_file="$js_all"
  if [ ! -f "$js_scan_file" ] || [ ! -s "$js_scan_file" ]; then
    js_scan_file="$js"
  fi
  if [ -f "$js_scan_file" ] && [ -s "$js_scan_file" ]; then
    echo -e "${YELLOW}[*] Running Mantra API key scan on JS files${NC}"
    if [ -n "$RATE" ]; then
      cat "$js_scan_file" | mantra -s -t "$RATE" | anew "$mantra_out" || true
    else
      cat "$js_scan_file" | mantra -s | anew "$mantra_out" || true
    fi
    echo -e "${GREEN}[+] Mantra scan complete: $(wc -l <"$mantra_out" 2>/dev/null || echo 0) findings${NC}"
  fi
fi

############################
# 5. Port Scan
############################
if [ "$SKIP_PORTSCAN" = false ]; then
  if [ ! -f "$ports" ]; then
    echo -e "${BLUE}[*] Running naabu port scan${NC}"
    if [ -n "$PROXY" ] && [ -n "$RATE" ]; then
      sed 's|https://||;s|http://||' "$live" | cut -d':' -f1 | naabu -silent -s s -verify -top-ports 1000 -rate "$RATE" -proxy "$PROXY" -o "$ports"
    elif [ -n "$PROXY" ]; then
      sed 's|https://||;s|http://||' "$live" | cut -d':' -f1 | naabu -silent -s s -verify -top-ports 1000 -proxy "$PROXY" -o "$ports"
    elif [ -n "$RATE" ]; then
      sed 's|https://||;s|http://||' "$live" | cut -d':' -f1 | naabu -silent -s s -verify -top-ports 1000 -rate "$RATE" -o "$ports"
    else
      sed 's|https://||;s|http://||' "$live" | cut -d':' -f1 | naabu -silent -s s -verify -top-ports 1000 -o "$ports"
    fi
    echo -e "${GREEN}[+] Open ports found: $(wc -l <"$ports")${NC}"
  fi
else
  echo -e "${YELLOW}[*] Skipping port scan${NC}"
fi

############################
# 5b. Screenshots
############################
if [ "$SKIP_SCREENSHOTS" = false ]; then
  if [ -f "$ports" ] && [ -s "$ports" ]; then
    echo -e "${BLUE}[*] Taking screenshots with gowitness${NC}"
    mkdir -p "$outdir/screenshots"
    sed 's/^/https:\/\//' "$ports" | gowitness scan file -f - -s "$outdir/screenshots" --no-http --write-jsonl --write-jsonl-file "$outdir/screenshots.jsonl" -q 2>/dev/null || true
    sed 's/^/http:\/\//' "$ports" | gowitness scan file -f - -s "$outdir/screenshots" --no-https --write-jsonl --write-jsonl-file "$outdir/screenshots.jsonl" -q 2>/dev/null || true
    screenshot_count=$(ls "$outdir/screenshots/"*.jpeg 2>/dev/null | wc -l)
    echo -e "${GREEN}[+] Screenshots saved: $screenshot_count${NC}"
  else
    echo -e "${YELLOW}[!] No ports to screenshot${NC}"
  fi
else
  echo -e "${YELLOW}[*] Skipping screenshots${NC}"
fi

############################
# 5c. XSS Scan
############################
if [ "$SKIP_XSS" = false ]; then
  if [ ! -f "$outdir/xss_results.txt" ]; then
    echo -e "${BLUE}[*] Gathering URLs for XSS scan${NC}"
    touch "$outdir/xss_urls.txt"
    if [ -f "$live" ] && [ -s "$live" ]; then
      cat "$live" | waybackurls 2>/dev/null | gf xss | anew "$outdir/xss_urls.txt" || true
    fi
    if [ -f "$outdir/katana_params.txt" ] && [ -s "$outdir/katana_params.txt" ]; then
      cat "$outdir/katana_params.txt" | gf xss | anew "$outdir/xss_urls.txt" || true
    fi
    if [ -s "$outdir/xss_urls.txt" ]; then
      echo -e "${BLUE}[*] Running dalfox XSS scan on $(wc -l <"$outdir/xss_urls.txt") URLs${NC}"
      cat "$outdir/xss_urls.txt" | qsreplace yogi | dalfox pipe --mining-dom --deep-domxss --mining-dict -o "$outdir/xss_results.txt" 2>/dev/null || true
      echo -e "${GREEN}[+] XSS findings: $(wc -l <"$outdir/xss_results.txt")${NC}"
    else
      echo -e "${YELLOW}[!] No XSS-prone URLs found${NC}"
      touch "$outdir/xss_results.txt"
    fi
  fi
else
  echo -e "${YELLOW}[*] Skipping XSS scan${NC}"
fi

############################
# 6. Nuclei Scan
############################
if [ "$SKIP_NUCLEI" = false ]; then
  if [ ! -f "$nuclei_out" ]; then
    echo -e "${BLUE}[*] Running nuclei scan${NC}"
    if [ -n "$PROXY" ] && [ -n "$RATE" ]; then
      nuclei -l "$live" -silent -rl "$RATE" -proxy "$PROXY" -o "$nuclei_out"
    elif [ -n "$PROXY" ]; then
      nuclei -l "$live" -silent -proxy "$PROXY" -o "$nuclei_out"
    elif [ -n "$RATE" ]; then
      nuclei -l "$live" -silent -rl "$RATE" -o "$nuclei_out"
    else
      nuclei -l "$live" -silent -o "$nuclei_out"
    fi
    if grep -qiE "critical|high" "$nuclei_out" 2>/dev/null; then
      notify -silent < "$nuclei_out"
    fi
    echo -e "${GREEN}[+] Nuclei findings: $(wc -l <"$nuclei_out")${NC}"
  fi
else
  echo -e "${YELLOW}[*] Skipping Nuclei scan${NC}"
fi

############################
# 7. Subdomain Permutations (alterx + puredns)
############################
alt_file="$outdir/alterx_subs.txt"
if [ ! -f "$resolved" ]; then
  echo -e "${BLUE}[*] Generating subdomain permutations with alterx${NC}"
  if [ -f "$subs" ] && [ -s "$subs" ]; then
    alterx -l "$subs" -silent -en -o "$alt_file" 2>/dev/null || true
    if [ -f "$alt_file" ] && [ -s "$alt_file" ]; then
      echo -e "${GREEN}[+] alterx generated $(wc -l <"$alt_file") permutations${NC}"
      echo -e "${BLUE}[*] Resolving with puredns${NC}"
      cat "$alt_file" | puredns resolve | anew "$resolved" || true
      echo -e "${GREEN}[+] Resolved $(wc -l <"$resolved") new subdomains${NC}"
    else
      echo -e "${YELLOW}[!] alterx generated no permutations${NC}"
      touch "$resolved"
    fi
  else
    echo -e "${YELLOW}[!] No subdomains to permute${NC}"
    touch "$resolved"
  fi
fi

############################
# HTML Report
############################
generate_report() {
  local dir="$1"
  local report_file="$dir/report.html"
  local domain
  domain=$(basename "$dir")

  local sub_count live_count ports_count screenshot_count xss_count scope_count nuclei_count mantra_count js_all_count katana_count params_count resolved_count
  sub_count=$([ -f "$dir/subdomains.txt" ] && wc -l < "$dir/subdomains.txt" || echo 0)
  live_count=$([ -f "$dir/live_hosts.txt" ] && wc -l < "$dir/live_hosts.txt" || echo 0)
  ports_count=$([ -f "$dir/ports.txt" ] && wc -l < "$dir/ports.txt" || echo 0)
  screenshot_count=$(ls "$dir/screenshots/"*.jpeg 2>/dev/null | wc -l)
  xss_count=$([ -f "$dir/xss_results.txt" ] && wc -l < "$dir/xss_results.txt" || echo 0)
  scope_count=$([ -f "$dir/broad_scope.txt" ] && wc -l < "$dir/broad_scope.txt" || echo 0)
  nuclei_count=$([ -f "$dir/nuclei_results.txt" ] && wc -l < "$dir/nuclei_results.txt" || echo 0)
  mantra_count=$([ -f "$dir/mantra_results.txt" ] && wc -l < "$dir/mantra_results.txt" || echo 0)
  js_all_count=$([ -f "$dir/all_js.txt" ] && wc -l < "$dir/all_js.txt" || echo 0)
  katana_count=$([ -f "$dir/katana_urls.txt" ] && wc -l < "$dir/katana_urls.txt" || echo 0)
  params_count=$([ -f "$dir/katana_params.txt" ] && wc -l < "$dir/katana_params.txt" || echo 0)
  resolved_count=$([ -f "$dir/resolved_subs.txt" ] && wc -l < "$dir/resolved_subs.txt" || echo 0)

  exec 3>"$report_file"

  cat >&3 << REPORT
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Recon Report - $domain</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Helvetica,Arial,sans-serif;background:#0d1117;color:#c9d1d9;padding:20px;font-size:14px;line-height:1.5}
a{color:#58a6ff;text-decoration:none}
a:hover{text-decoration:underline;color:#79c0ff}
.report-header{max-width:1200px;margin:0 auto 24px}
.report-header h1{font-size:28px;font-weight:600;color:#f0f6fc;margin-bottom:4px}
.report-header .subtitle{color:#8b949e;font-size:14px}
.stats{display:grid;grid-template-columns:repeat(auto-fit,minmax(120px,1fr));gap:12px;margin:0 auto 24px;max-width:1200px}
.stat-card{background:#161b22;border:1px solid #30363d;border-radius:8px;padding:16px;text-align:center}
.stat-card .num{font-size:24px;font-weight:700;color:#f0f6fc}
.stat-card .label{font-size:11px;color:#8b949e;text-transform:uppercase;letter-spacing:.5px;margin-top:4px}
.search-bar{max-width:1200px;margin:0 auto 24px}
.search-bar input{width:100%;padding:10px 14px;background:#0d1117;border:1px solid #30363d;border-radius:8px;color:#c9d1d9;font-size:14px;outline:none;transition:border-color .2s}
.search-bar input:focus{border-color:#58a6ff}
.section{max-width:1200px;margin:0 auto 24px;background:#161b22;border:1px solid #30363d;border-radius:8px;overflow:hidden}
.section-header{padding:14px 18px;background:#1c2128;border-bottom:1px solid #30363d;display:flex;justify-content:space-between;align-items:center;cursor:pointer;user-select:none}
.section-header:hover{background:#21262d}
.section-header h2{font-size:15px;font-weight:600;color:#f0f6fc}
.section-header .count{background:#30363d;color:#c9d1d9;padding:2px 10px;border-radius:12px;font-size:12px;font-weight:500}
.section-body{padding:0}
.section-body table{width:100%;border-collapse:collapse}
.section-body td{padding:8px 18px;border-bottom:1px solid #21262d;word-break:break-all;font-family:'SF Mono','Fira Code','Consolas',monospace;font-size:13px}
.section-body tr:last-child td{border-bottom:none}
.section-body tr:hover{background:#1c2128}
.badge{display:inline-block;padding:1px 8px;border-radius:10px;font-size:11px;font-weight:600;text-transform:uppercase;margin-right:6px}
.badge-critical{background:#da3633;color:#fff}
.badge-high{background:#d29922;color:#fff}
.badge-medium{background:#9e6a03;color:#fff}
.badge-low{background:#1f6feb;color:#fff}
.badge-info{background:#30363d;color:#c9d1d9}
.badge-http{background:#1f6feb20;color:#58a6ff;border:1px solid #1f6feb40}
.badge-https{background:#23863620;color:#3fb950;border:1px solid #23863640}
.empty-state{padding:32px 18px;text-align:center;color:#8b949e;font-size:13px}
.secret-finding{color:#f0883e}
.nuclei-line{font-family:'SF Mono','Fira Code','Consolas',monospace;font-size:12px;padding:4px 0}
.param-url{color:#d2a8ff}
.tech-cell{display:flex;flex-wrap:wrap;gap:4px}
.tech-badge{display:inline-block;padding:1px 7px;border-radius:4px;font-size:10px;font-weight:600;background:#1c2128;border:1px solid #30363d;color:#8b949e}
.tech-badge:nth-child(6n+1){border-color:#da363340;color:#f85149}
.tech-badge:nth-child(6n+2){border-color:#d2992240;color:#d29922}
.tech-badge:nth-child(6n+3){border-color:#1f6feb40;color:#58a6ff}
.tech-badge:nth-child(6n+4){border-color:#23863640;color:#3fb950}
.tech-badge:nth-child(6n+5){border-color:#bc8cff40;color:#bc8cff}
.tech-badge:nth-child(6n+6){border-color:#f0883e40;color:#f0883e}
.notice{padding:10px 18px;background:#1c2128;border-top:1px solid #30363d;text-align:center;color:#8b949e;font-size:12px}
@media(max-width:600px){.stats{grid-template-columns:repeat(2,1fr)}
</style>
</head>
<body>
REPORT

  printf >&3 '\n<div class="report-header"><h1>Recon Report: <span style="color:#58a6ff">%s</span></h1><div class="subtitle">Generated %s</div></div>\n' "$domain" "$(date '+%Y-%m-%d %H:%M')"

  printf >&3 '\n<div class="stats">'
  printf >&3 '\n<div class="stat-card"><div class="num">%s</div><div class="label">Subdomains</div></div>' "$sub_count"
  printf >&3 '\n<div class="stat-card"><div class="num">%s</div><div class="label">Live Hosts</div></div>' "$live_count"
  printf >&3 '\n<div class="stat-card"><div class="num">%s</div><div class="label">Open Ports</div></div>' "$ports_count"
  [ "$scope_count" -gt 0 ] 2>/dev/null && printf >&3 '\n<div class="stat-card"><div class="num">%s</div><div class="label">Scope CIDRs</div></div>' "$scope_count" || true
  [ "$screenshot_count" -gt 0 ] 2>/dev/null && printf >&3 '\n<div class="stat-card"><div class="num">%s</div><div class="label">Screenshots</div></div>' "$screenshot_count" || true
  [ "$xss_count" -gt 0 ] 2>/dev/null && printf >&3 '\n<div class="stat-card"><div class="num" style="color:#d29922">%s</div><div class="label">XSS Findings</div></div>' "$xss_count" || true
  [ "$resolved_count" -gt 0 ] 2>/dev/null && printf >&3 '\n<div class="stat-card"><div class="num">%s</div><div class="label">Resolved Subs</div></div>' "$resolved_count" || true
  [ "$nuclei_count" -gt 0 ] 2>/dev/null && printf >&3 '\n<div class="stat-card"><div class="num" style="color:#da3633">%s</div><div class="label">Nuclei Findings</div></div>' "$nuclei_count" || true
  [ "$mantra_count" -gt 0 ] 2>/dev/null && printf >&3 '\n<div class="stat-card"><div class="num" style="color:#f0883e">%s</div><div class="label">Secrets</div></div>' "$mantra_count" || true
  [ "$katana_count" -gt 0 ] 2>/dev/null && printf >&3 '\n<div class="stat-card"><div class="num">%s</div><div class="label">Crawled URLs</div></div>' "$katana_count" || true
  [ "$params_count" -gt 0 ] 2>/dev/null && printf >&3 '\n<div class="stat-card"><div class="num">%s</div><div class="label">URLs w/ Params</div></div>' "$params_count" || true
  printf >&3 '\n</div>'

  cat >&3 << 'REPORT'
<div class="search-bar"><input type="text" id="searchInput" placeholder="Filter across all sections..." onkeyup="filterAll()"></div>
REPORT

  html_row() { printf >&3 '    <tr><td>%s</td></tr>\n' "$1"; }

  section_header() { printf >&3 '\n<div class="section"><div class="section-header" onclick="toggleBody(this)"><h2>%s</h2><span class="count">%s</span></div><div class="section-body">\n' "$1" "$2"; }
  section_footer() { printf >&3 '</div></div>\n'; }

  section_header "Live Subdomains" "$live_count"
  if [ -f "$dir/live_hosts.txt" ] && [ -s "$dir/live_hosts.txt" ]; then
    printf >&3 '<table>\n'
    while IFS= read -r host || [ -n "$host" ]; do
      [ -z "$host" ] && continue
      local scheme_class="badge-https"
      case "$host" in http://*) scheme_class="badge-http" ;; esac
      local escaped
      escaped=$(printf '%s' "$host" | sed 's/&/\&amp;/g; s/</\&lt;/g; s/>/\&gt;/g; s/"/\&quot;/g')
      local display
      display=$(printf '%s' "$host" | sed 's|https://||;s|http://||')
      local tech_line tech
      tech_line=""
      [ -f "$dir/tech_stack.txt" ] && tech_line=$(grep -F "$host:" "$dir/tech_stack.txt" 2>/dev/null || true)
      if [ -n "$tech_line" ]; then
        tech=$(printf '%s' "$tech_line" | cut -d' ' -f2-)
        local tech_html=""
        local IFS=,
        for t in $tech; do
          t=$(printf '%s' "$t" | sed 's/^ *//;s/ *$//;s/&/\&amp;/g;s/</\&lt;/g;s/>/\&gt;/g;s/"/\&quot;/g')
          tech_html="$tech_html<span class=\"tech-badge\">$t</span>"
        done
        unset IFS
        printf >&3 '<tr><td style="width:60%%"><a href="%s" target="_blank" rel="noopener"><span class="badge %s">%s</span>%s</a></td><td style="width:40%%"><div class="tech-cell">%s</div></td></tr>\n' "$escaped" "$scheme_class" "$(printf '%s' "$host" | grep -q '^http://' && echo 'HTTP' || echo 'HTTPS')" "$display" "$tech_html"
      else
        printf >&3 '<tr><td><a href="%s" target="_blank" rel="noopener"><span class="badge %s">%s</span>%s</a></td><td></td></tr>\n' "$escaped" "$scheme_class" "$(printf '%s' "$host" | grep -q '^http://' && echo 'HTTP' || echo 'HTTPS')" "$display"
      fi
    done < "$dir/live_hosts.txt"
    printf >&3 '</table>\n'
  else
    printf >&3 '<div class="empty-state">No live hosts found</div>\n'
  fi
  section_footer

  section_header "Scope (CIDR Ranges)" "$scope_count"
  if [ -f "$dir/cidr_ranges.txt" ] && [ -s "$dir/cidr_ranges.txt" ]; then
    printf >&3 '<table>\n'
    while IFS= read -r line || [ -n "$line" ]; do
      [ -z "$line" ] && continue
      local escaped
      escaped=$(printf '%s' "$line" | sed 's/&/\&amp;/g; s/</\&lt;/g; s/>/\&gt;/g; s/"/\&quot;/g')
      printf >&3 '<tr><td><span class="badge badge-info">CIDR</span>%s</td></tr>\n' "$escaped"
    done < "$dir/cidr_ranges.txt"
    printf >&3 '</table>\n'
  else
    printf >&3 '<div class="empty-state">No CIDR ranges discovered</div>\n'
  fi
  section_footer

  section_header "Open Ports" "$ports_count"
  if [ -f "$dir/ports.txt" ] && [ -s "$dir/ports.txt" ]; then
    printf >&3 '<table>\n'
    while IFS= read -r line || [ -n "$line" ]; do
      [ -z "$line" ] && continue
      local escaped
      escaped=$(printf '%s' "$line" | sed 's/&/\&amp;/g; s/</\&lt;/g; s/>/\&gt;/g; s/"/\&quot;/g')
      printf >&3 '<tr><td><span class="badge badge-critical">OPEN</span>%s</td></tr>\n' "$escaped"
    done < "$dir/ports.txt"
    printf >&3 '</table>\n'
  else
    printf >&3 '<div class="empty-state">No open ports found</div>\n'
  fi
  section_footer

  cat >&3 << 'REPORT'
<div class="section"><div class="section-header" onclick="toggleBody(this)"><h2>Potentially Vulnerable URLs</h2><span class="count">VULNS</span></div><div class="section-body">
REPORT

  if [ -f "$dir/katana_params.txt" ] && [ -s "$dir/katana_params.txt" ]; then
    printf >&3 '<div style="padding:10px 18px;background:#1c2128;border-bottom:1px solid #30363d;font-size:13px;font-weight:600;color:#d2a8ff">URLs with Query Parameters (%s)</div>\n' "$params_count"
    printf >&3 '<table>\n'
    local pcount=0
    while IFS= read -r url || [ -n "$url" ]; do
      [ -z "$url" ] && continue
      pcount=$((pcount + 1))
      [ "$pcount" -gt 200 ] && continue
      local escaped
      escaped=$(printf '%s' "$url" | sed 's/&/\&amp;/g; s/</\&lt;/g; s/>/\&gt;/g; s/"/\&quot;/g')
      printf >&3 '<tr><td class="param-url"><a href="%s" target="_blank" rel="noopener">%s</a></td></tr>\n' "$escaped" "$escaped"
    done < "$dir/katana_params.txt"
    printf >&3 '</table>\n'
    [ "$params_count" -gt 200 ] && printf >&3 '<div class="notice">Showing 200 of %s entries</div>\n' "$params_count"
  fi

  if [ -f "$dir/nuclei_results.txt" ] && [ -s "$dir/nuclei_results.txt" ]; then
    printf >&3 '<div style="padding:10px 18px;background:#1c2128;border-bottom:1px solid #30363d;font-size:13px;font-weight:600;color:#da3633">Nuclei Findings (%s)</div>\n' "$nuclei_count"
    printf >&3 '<table>\n'
    while IFS= read -r line || [ -n "$line" ]; do
      [ -z "$line" ] && continue
      local escaped line_lower severity badge
      escaped=$(printf '%s' "$line" | sed 's/&/\&amp;/g; s/</\&lt;/g; s/>/\&gt;/g; s/"/\&quot;/g')
      line_lower=$(printf '%s' "$line" | tr '[:upper:]' '[:lower:]')
      severity="info"
      case "$line_lower" in *critical*) severity="critical"; badge="badge-critical" ;; *high*) severity="high"; badge="badge-high" ;; *medium*) severity="medium"; badge="badge-medium" ;; *low*) severity="low"; badge="badge-low" ;; *) severity="info"; badge="badge-info" ;; esac
      printf >&3 '<tr><td><span class="badge %s">%s</span><span class="nuclei-line">%s</span></td></tr>\n' "$badge" "$severity" "$escaped"
    done < "$dir/nuclei_results.txt"
    printf >&3 '</table>\n'
  fi

  if [ -f "$dir/mantra_results.txt" ] && [ -s "$dir/mantra_results.txt" ]; then
    printf >&3 '<div style="padding:10px 18px;background:#1c2128;border-bottom:1px solid #30363d;font-size:13px;font-weight:600;color:#f0883e">Mantra Secrets (%s)</div>\n' "$mantra_count"
    printf >&3 '<table>\n'
    while IFS= read -r line || [ -n "$line" ]; do
      [ -z "$line" ] && continue
      local cleaned
      cleaned=$(printf '%s' "$line" | sed 's/\x1b\[[0-9;]*m//g; s/&/\&amp;/g; s/</\&lt;/g; s/>/\&gt;/g; s/"/\&quot;/g')
      printf >&3 '<tr><td class="secret-finding">%s</td></tr>\n' "$cleaned"
    done < "$dir/mantra_results.txt"
    printf >&3 '</table>\n'
  fi

  if { [ ! -f "$dir/katana_params.txt" ] || [ ! -s "$dir/katana_params.txt" ]; } && { [ ! -f "$dir/nuclei_results.txt" ] || [ ! -s "$dir/nuclei_results.txt" ]; } && { [ ! -f "$dir/mantra_results.txt" ] || [ ! -s "$dir/mantra_results.txt" ]; }; then
    printf >&3 '<div class="empty-state">No potentially vulnerable URLs found</div>\n'
  fi
  section_footer

  section_header "Screenshots" "$screenshot_count"
  if [ -d "$dir/screenshots" ] && [ "$screenshot_count" -gt 0 ]; then
    printf >&3 '<div style="display:grid;grid-template-columns:repeat(auto-fill,minmax(300px,1fr));gap:12px;padding:12px">\n'
    for img in "$dir/screenshots/"*.jpeg; do
      [ -f "$img" ] || continue
      local img_name
      img_name=$(basename "$img" .jpeg)
      local escaped_img
      escaped_img=$(printf '%s' "$img_name" | sed 's/&/\&amp;/g; s/</\&lt;/g; s/>/\&gt;/g; s/"/\&quot;/g')
      printf >&3 '<div style="border:1px solid #30363d;border-radius:8px;overflow:hidden;background:#1c2128"><div style="padding:8px 12px;font-size:12px;border-bottom:1px solid #30363d;color:#8b949e">%s</div><a href="screenshots/%s.jpeg" target="_blank"><img src="screenshots/%s.jpeg" style="width:100%%;display:block" loading="lazy"></a></div>\n' "$escaped_img" "$img_name" "$img_name"
    done
    printf >&3 '</div>\n'
  else
    printf >&3 '<div class="empty-state">No screenshots taken</div>\n'
  fi
  section_footer

  section_header "XSS Findings" "$xss_count"
  if [ -f "$dir/xss_results.txt" ] && [ -s "$dir/xss_results.txt" ]; then
    printf >&3 '<table>\n'
    while IFS= read -r line || [ -n "$line" ]; do
      [ -z "$line" ] && continue
      local escaped
      escaped=$(printf '%s' "$line" | sed 's/&/\&amp;/g; s/</\&lt;/g; s/>/\&gt;/g; s/"/\&quot;/g')
      printf >&3 '<tr><td style="color:#d29922;font-size:12px">%s</td></tr>\n' "$escaped"
    done < "$dir/xss_results.txt"
    printf >&3 '</table>\n'
  else
    printf >&3 '<div class="empty-state">No XSS vulnerabilities found</div>\n'
  fi
  section_footer

  section_header "JavaScript Files" "$js_all_count"
  if [ -f "$dir/all_js.txt" ] && [ -s "$dir/all_js.txt" ]; then
    printf >&3 '<table>\n'
    while IFS= read -r url || [ -n "$url" ]; do
      [ -z "$url" ] && continue
      local escaped
      escaped=$(printf '%s' "$url" | sed 's/&/\&amp;/g; s/</\&lt;/g; s/>/\&gt;/g; s/"/\&quot;/g')
      printf >&3 '<tr><td><a href="%s" target="_blank" rel="noopener">%s</a></td></tr>\n' "$escaped" "$escaped"
    done < "$dir/all_js.txt"
    printf >&3 '</table>\n'
  else
    printf >&3 '<div class="empty-state">No JS files found</div>\n'
  fi
  section_footer

  section_header "Katana Crawl Results" "$katana_count"
  if [ -f "$dir/katana_urls.txt" ] && [ -s "$dir/katana_urls.txt" ]; then
    printf >&3 '<table>\n'
    local kcount=0
    while IFS= read -r url || [ -n "$url" ]; do
      [ -z "$url" ] && continue
      kcount=$((kcount + 1))
      [ "$kcount" -gt 500 ] && continue
      local escaped
      escaped=$(printf '%s' "$url" | sed 's/&/\&amp;/g; s/</\&lt;/g; s/>/\&gt;/g; s/"/\&quot;/g')
      printf >&3 '<tr><td><a href="%s" target="_blank" rel="noopener">%s</a></td></tr>\n' "$escaped" "$escaped"
    done < "$dir/katana_urls.txt"
    printf >&3 '</table>\n'
    [ "$katana_count" -gt 500 ] && printf >&3 '<div class="notice">Showing 500 of %s entries</div>\n' "$katana_count"
  else
    printf >&3 '<div class="empty-state">No katana URLs found</div>\n'
  fi
  section_footer

  section_header "Resolved Subdomains (alterx + puredns)" "$resolved_count"
  if [ -f "$dir/resolved_subs.txt" ] && [ -s "$dir/resolved_subs.txt" ]; then
    printf >&3 '<table>\n'
    while IFS= read -r host || [ -n "$host" ]; do
      [ -z "$host" ] && continue
      local escaped
      escaped=$(printf '%s' "$host" | sed 's/&/\&amp;/g; s/</\&lt;/g; s/>/\&gt;/g; s/"/\&quot;/g')
      printf >&3 '<tr><td><a href="http://%s" target="_blank" rel="noopener">%s</a></td></tr>\n' "$escaped" "$escaped"
    done < "$dir/resolved_subs.txt"
    printf >&3 '</table>\n'
  else
    printf >&3 '<div class="empty-state">No resolved subdomains found</div>\n'
  fi
  section_footer

  cat >&3 << 'REPORT'
<script>
function toggleBody(header){var body=header.nextElementSibling;if(body.style.display==='none'){body.style.display=''}else{body.style.display='none'}}
function filterAll(){var input=document.getElementById('searchInput');var filter=input.value.toUpperCase();var sections=document.querySelectorAll('.section');for(var i=0;i<sections.length;i++){var section=sections[i];var body=section.querySelector('.section-body');var rows=body?body.querySelectorAll('tr'):[];var hasMatch=false;for(var j=0;j<rows.length;j++){var text=rows[j].textContent||rows[j].innerText;if(text.toUpperCase().indexOf(filter)>-1){rows[j].style.display='';hasMatch=true}else{rows[j].style.display='none'}}if(body&&rows.length===0){continue}var header=section.querySelector('.section-header');if(hasMatch){section.style.display=''}else{section.style.display='none'}}}
</script>
</body>
</html>
REPORT

  exec 3>&-
  echo -e "${GREEN}[+] HTML report saved: $report_file${NC}"
}

generate_report "$outdir"

############################
# Final Summary
############################
echo -e "\n${YELLOW}========== FINAL SUMMARY ==========${NC}"
echo -e "Subdomains     : $([ -f "$subs" ] && wc -l <"$subs" || echo 0)"
echo -e "Live Hosts     : $([ -f "$live" ] && wc -l <"$live" || echo 0)"
echo -e "Scope CIDRs    : $([ -f "$cidr_file" ] && wc -l <"$cidr_file" || echo 0)"
echo -e "JS Files       : $([ -f "$js" ] && wc -l <"$js" || echo 0)"
echo -e "All JS Files   : $([ -f "$js_all" ] && wc -l <"$js_all" || echo 0)"
echo -e "Katana URLs    : $([ -f "$outdir/katana_urls.txt" ] && wc -l <"$outdir/katana_urls.txt" || echo 0)"
echo -e "Open Ports     : $([ -f "$ports" ] && wc -l <"$ports" || echo 0)"
echo -e "Screenshots    : $(ls "$outdir/screenshots/"*.jpeg 2>/dev/null | wc -l)"
echo -e "XSS Findings   : $([ -f "$outdir/xss_results.txt" ] && wc -l <"$outdir/xss_results.txt" || echo 0)"
echo -e "Resolved Subs  : $([ -f "$resolved" ] && wc -l <"$resolved" || echo 0)"
if [ -n "$PROXY" ]; then
  echo -e "Proxy         : $PROXY"
fi
if [ -n "$RATE" ]; then
  echo -e "Rate          : $RATE req/sec"
fi
if [ "$SKIP_NUCLEI" = false ]; then
  echo -e "Nuclei Results : $(wc -l <"$nuclei_out" 2>/dev/null || echo 0)"
else
  echo -e "Nuclei Results : SKIPPED"
fi
if [ "$SKIP_JSLEAKS" = false ] && [ "$SKIP_KATANA" = false ]; then
  echo -e "Mantra Keys   : $(wc -l <"$mantra_out" 2>/dev/null || echo 0)"
else
  echo -e "Mantra Keys   : SKIPPED"
fi
echo -e "${YELLOW}===================================${NC}"
