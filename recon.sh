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
  --skip-jsleaks          Skip JS leaks detection
  --skip-cors             Skip CORS misconfiguration scan
  --skip-screenshots      Skip httpx screenshots
  --skip-portscan         Skip naabu port scan
  --skip-katana           Skip Katana crawl (JS, params extraction)

${YELLOW}EXAMPLES:${NC}
  $0 example.com
  $0 example.com --skip-nuclei --skip-jsleaks
  $0 example.com --skip-screenshots --skip-cors
  $0 example.com --skip-nuclei --skip-jsleaks --skip-cors --skip-screenshots

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
    8. JS Leaks Detection (custom nuclei templates)
    9. Screenshots (httpx)
    10. HTTP Response Archival
    11. CORS Misconfiguration Scan (Corsy)

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
SKIP_SCREENSHOTS=false
SKIP_PORTSCAN=false
SKIP_KATANA=false

# Parse flags first
for arg in "$@"; do
  case "$arg" in
    --help|-h)
      show_help
      ;;
  esac
done

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
    --skip-nuclei)
      SKIP_NUCLEI=true
      ;;
    --skip-jsleaks)
      SKIP_JSLEAKS=true
      ;;
    --skip-cors)
      SKIP_CORS=true
      ;;
    --skip-screenshots)
      SKIP_SCREENSHOTS=true
      ;;
    --skip-portscan)
      SKIP_PORTSCAN=true
      ;;
    --skip-katana)
      SKIP_KATANA=true
      ;;
    *)
      echo -e "${RED}[!] Unknown option: $1${NC}"
      echo -e "${YELLOW}Run '$0 --help' for more information.${NC}"
      exit 1
      ;;
  esac
  shift
done

############################
# Check Target
############################
outdir=$domain
mkdir -p "$outdir"/screenshots

############################
# Required Tools
############################
tools=(subfinder assetfinder amass httpx gau waybackurls naabu nuclei anew katana notify)

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
live="$outdir/live_hosts.txt"
urls="$outdir/urls.txt"
params="$outdir/params.txt"
js="$outdir/jsfiles.txt"
wayback="$outdir/wayback_urls.txt"
ports="$outdir/ports.txt"
nuclei_out="$outdir/nuclei_results.txt"

############################
# 1. Subdomain Enumeration
############################
if [ ! -f "$subs" ]; then
  echo -e "${BLUE}[*] Running subdomain enumeration${NC}"
  (
    subfinder -d "$domain" -silent
    assetfinder --subs-only "$domain"
    amass enum -passive -d "$domain"
    chaos -d "$domain" -silent 2>/dev/null || true
  ) | anew "$subs"
  echo -e "${GREEN}[+] Found $(wc -l <"$subs") subdomains${NC}"
fi

############################
# 2. Live Hosts
############################
if [ ! -f "$live" ]; then
  echo -e "${BLUE}[*] Checking live hosts${NC}"
  cat "$subs" | httpx -silent -threads 100 | anew "$live"
  echo -e "${GREEN}[+] Live hosts: $(wc -l <"$live")${NC}"
fi

############################
# 3. URL Collection
############################
if [ ! -f "$urls" ]; then
  echo -e "${BLUE}[*] Collecting URLs (gau + wayback)${NC}"
  (
    proxychains gau "$domain" 2>/dev/null
    proxychains waybackurls "$domain" 2>/dev/null
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
    katana -list "$live" -d 3 -jc -jsluice -ef woff,css,svg,png,jpg,gif -silent | anew "$outdir/katana_urls.txt"

    echo -e "${YELLOW}[*] Extracting JS files from katana crawl${NC}"
    grep -E ".*\.js($|\\?.*)" "$outdir/katana_urls.txt" | anew "$js_all" || true

    echo -e "${YELLOW}[*] Extracting URLs with query parameters from katana${NC}"
    grep "=" "$outdir/katana_urls.txt" | anew "$outdir/katana_params.txt" || true

    echo -e "${GREEN}[+] Katana URLs: $(wc -l <"$outdir/katana_urls.txt" 2>/dev/null || echo 0)${NC}"
    echo -e "${GREEN}[+] Total JS files: $(wc -l <"$js_all" 2>/dev/null || echo 0)${NC}"
  fi

  if [ -f "$js_all" ] && [ -s "$js_all" ] && [ "$SKIP_JSLEAKS" = false ]; then
    echo -e "${YELLOW}[*] Running nuclei JS leak detection${NC}"
    nuclei -l "$js_all" -t /home/gun/my-nuclei-templates/js-leaks.yaml -silent | tee "$outdir/js_leaks_results.txt"
    if grep -qiE "critical|high" "$outdir/js_leaks_results.txt" 2>/dev/null; then
      notify -silent < "$outdir/js_leaks_results.txt"
    fi
    echo -e "${GREEN}[+] JS leak scan complete${NC}"
  fi
else
  echo -e "${YELLOW}[*] Skipping Katana crawl and related extractions${NC}"
  js="$outdir/jsfiles.txt"
  js_all="$outdir/all_js.txt"
fi

############################
# 6. Port Scan
############################
if [ "$SKIP_PORTSCAN" = false ]; then
  if [ ! -f "$ports" ]; then
    echo -e "${BLUE}[*] Running naabu port scan${NC}"
    cat "$subs" | naabu -silent -top-ports 1000 | anew "$ports"
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
    proxychains nuclei -l "$live" -silent -o "$nuclei_out"
    if grep -qiE "critical|high" "$nuclei_out" 2>/dev/null; then
      notify -silent < "$nuclei_out"
    fi
    echo -e "${GREEN}[+] Nuclei findings: $(wc -l <"$nuclei_out")${NC}"
  fi
else
  echo -e "${YELLOW}[*] Skipping Nuclei scan${NC}"
fi

############################
# 8. Screenshots
############################
if [ "$SKIP_SCREENSHOTS" = false ]; then
  if [ -z "$(ls -A "$outdir/screenshots" 2>/dev/null)" ]; then
    echo -e "${BLUE}[*] Taking screenshots with httpx (fast)${NC}"
    cat "$live" | httpx -silent -threads 50 -screenshot -store-response -store-response-dir "$outdir/screenshots"
    echo -e "${GREEN}[+] Screenshots complete${NC}"
  fi
else
  echo -e "${YELLOW}[*] Skipping screenshots${NC}"
fi

############################
# 10. CORS Misconfiguration Scan
############################
cors_out="$outdir/cors_results.txt"
if [ "$SKIP_CORS" = false ]; then
  if [ ! -f "$cors_out" ]; then
    echo -e "${BLUE}[*] Running CORS misconfiguration scan with Corsy${NC}"
    (
      source /home/gun/Desktop/web-hacking-tools/Corsy/venv/bin/activate
      python3 /home/gun/Desktop/web-hacking-tools/Corsy/corsy.py -i "$live" -t 2 -d 2
    ) | tee "$cors_out"
    if grep -qiE "critical|high" "$cors_out" 2>/dev/null; then
      notify -silent < "$cors_out"
    fi
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
if [ "$SKIP_NUCLEI" = false ]; then
  echo -e "Nuclei Results : $(wc -l <"$nuclei_out" 2>/dev/null || echo 0)"
else
  echo -e "Nuclei Results : SKIPPED"
fi
if [ "$SKIP_JSLEAKS" = false ] || [ "$SKIP_KATANA" = false ]; then
  echo -e "JS Leaks       : $(wc -l <"$outdir/js_leaks_results.txt" 2>/dev/null || echo 0)"
else
  echo -e "JS Leaks       : SKIPPED"
fi
if [ "$SKIP_CORS" = false ]; then
  echo -e "CORS Findings  : $(wc -l <"$cors_out" 2>/dev/null || echo 0)"
else
  echo -e "CORS Findings  : SKIPPED"
fi
echo -e "${YELLOW}===================================${NC}"
