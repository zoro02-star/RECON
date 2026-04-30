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
  --skip-nuclei           Skip Nuclei vulnerability scan
  --skip-jsleaks          Skip Mantra JS secret scan
  --skip-cors             Skip CORS misconfiguration scan
  --skip-portscan         Skip naabu port scan
  --skip-katana           Skip Katana crawl (JS, params extraction)
  --proxy                 Proxy URL (e.g., http://localhost:8080 for Caido)
  --rate, -c             Requests per second (e.g., -c 5 for 5 req/sec)

${YELLOW}EXAMPLES:${NC}
  $0 example.com
  $0 example.com --skip-nuclei --skip-jsleaks
  $0 example.com --skip-nuclei --skip-jsleaks --skip-cors
  $0 example.com --proxy http://localhost:8080
  $0 example.com --proxy http://127.0.0.1:8080 --skip-nuclei
  $0 example.com -c 5
  $0 example.com -c 10 --proxy http://localhost:8080

${YELLOW}DESCRIPTION:${NC}
  This script automates the reconnaissance process for a given target domain.
  It performs the following steps in order:
    1. Subdomain Enumeration (subfinder, assetfinder, amass, chaos)
    2. Live Host Detection (httpx)
    3. URL Collection (gau, waybackurls)
    4. Parameter & JS File Extraction
    5. Katana Crawl (deep URL/JS/params discovery)
    6. Port Scanning (naabu)
    7. Vulnerability Scanning (nuclei)
    8. Mantra JS Secret Scan (API key leak detection)
    9. CORS Misconfiguration Scan (Corsy)

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
SKIP_CORS=false
SKIP_PORTSCAN=false
SKIP_KATANA=false
PROXY=""
RATE=""

# Handle help flag before anything else
if [[ "$1" == "--help" ]] || [[ "$1" == "-h" ]]; then
  show_help
fi

# First non-flag argument must be the domain
if [ $# -lt 1 ]; then
  echo -e "${YELLOW}Usage: $0 target-domain.com [OPTIONS]${NC}"
  echo -e "${YELLOW}Run '$0 --help' for more information.${NC}"
  exit 1
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
    --skip-cors)
      SKIP_CORS=true
      ;;
    --skip-portscan)
      SKIP_PORTSCAN=true
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
    -c)
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
tools=(subfinder assetfinder amass httpx gau waybackurls naabu nuclei anew katana notify mantra)

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
urls="$outdir/urls.txt"
params="$outdir/params.txt"
js="$outdir/jsfiles.txt"
wayback="$outdir/wayback_urls.txt"
ports="$outdir/ports.txt"
nuclei_out="$outdir/nuclei_results.txt"
mantra_out="$outdir/mantra_results.txt"

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
# 3. URL Collection
############################
if [ ! -f "$urls" ]; then
  echo -e "${BLUE}[*] Collecting URLs (gau + wayback)${NC}"
  (
    if [ -n "$PROXY" ] && [ -n "$RATE" ]; then
      gau "$domain" --proxy "$PROXY" --threads "$RATE" 2>/dev/null
      waybackurls "$domain" 2>/dev/null
    elif [ -n "$PROXY" ]; then
      gau "$domain" --proxy "$PROXY" 2>/dev/null
      waybackurls "$domain" 2>/dev/null
    elif [ -n "$RATE" ]; then
      gau "$domain" --threads "$RATE" 2>/dev/null
      waybackurls "$domain" 2>/dev/null
    else
      gau "$domain" 2>/dev/null
      waybackurls "$domain" 2>/dev/null
    fi
  ) | anew "$urls"
  echo -e "${GREEN}[+] URLs collected: $(wc -l <"$urls")${NC}"
fi

############################
# 4. Wayback Only File
############################
if [ ! -f "$wayback" ]; then
  grep "web.archive.org" "$urls" | anew "$wayback" || true
fi

############################
# 5. Params + JS + Katana Crawl
############################
if [ "$SKIP_KATANA" = false ]; then
  if [ ! -f "$params" ]; then
    echo -e "${BLUE}[*] Extracting parameters${NC}"
    grep "=" "$urls" | anew "$params" || true
  fi

  js="$outdir/jsfiles.txt"
  js_all="$outdir/all_js.txt"

  if [ ! -f "$js" ]; then
    echo -e "${BLUE}[*] Extracting JS files from collected URLs${NC}"
    grep -E ".*\.js($|\\?.*)" "$urls" | anew "$js" || true
  fi

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
# 5b. Mantra JS Secret Scan
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
# 6. Port Scan
############################
if [ "$SKIP_PORTSCAN" = false ]; then
  if [ ! -f "$ports" ]; then
    echo -e "${BLUE}[*] Running naabu port scan${NC}"
    cat "$live" | sed 's|https://||;s|http://||' | cut -d':' -f1 | naabu -silent -top-ports 1000 | anew "$ports"
    echo -e "${GREEN}[+] Open ports found: $(wc -l <"$ports")${NC}"
  fi
else
  echo -e "${YELLOW}[*] Skipping port scan${NC}"
fi

############################
# 7. Nuclei Scan
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
# 8. CORS Misconfiguration Scan
############################
cors_out="$outdir/cors_results.txt"
CORSY_PATH="/home/harsh/Desktop/Corsy/corsy.py"
VENV_PATH="/home/harsh/Desktop/Corsy/venv/bin/activate"

if [ "$SKIP_CORS" = false ]; then
  if [ ! -f "$cors_out" ]; then
    echo -e "${BLUE}[*] Running CORS misconfiguration scan with Corsy${NC}"
    (
      source /home/harsh/Desktop/Corsy/venv/bin/activate
      cd /home/harsh/Desktop/Corsy
      proxychains python3 corsy.py -i "$live" -t 2
    ) | anew "$cors_out"
    echo -e "${GREEN}[+] CORS findings: $(wc -l <"$cors_out" 2>/dev/null || echo 0)${NC}"
  fi
else
  echo -e "${YELLOW}[*] Skipping CORS scan${NC}"
fi

############################
# Final Summary
############################
echo -e "\n${YELLOW}========== FINAL SUMMARY ==========${NC}"
echo -e "Subdomains     : $(wc -l <"$subs" 2>/dev/null || echo 0)"
echo -e "Live Hosts     : $(wc -l <"$live" 2>/dev/null || echo 0)"
echo -e "URLs           : $(wc -l <"$urls" 2>/dev/null || echo 0)"
echo -e "Parameters     : $(wc -l <"$params" 2>/dev/null || echo 0)"
echo -e "JS Files       : $(wc -l <"$js" 2>/dev/null || echo 0)"
echo -e "All JS Files   : $(wc -l <"$js_all" 2>/dev/null || echo 0)"
echo -e "Katana URLs    : $(wc -l <"$outdir/katana_urls.txt" 2>/dev/null || echo 0)"
echo -e "Open Ports     : $(wc -l <"$ports" 2>/dev/null || echo 0)"
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
if [ "$SKIP_CORS" = false ]; then
  echo -e "CORS Findings  : $(wc -l <"$cors_out" 2>/dev/null || echo 0)"
else
  echo -e "CORS Findings  : SKIPPED"
fi
echo -e "${YELLOW}===================================${NC}"
