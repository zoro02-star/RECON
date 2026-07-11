#!/usr/bin/env bash

set -euo pipefail

# Ensure user's Go tool bins are in PATH (needed when running via sudo)
REAL_USER="${SUDO_USER:-$USER}"
REAL_HOME=$(eval echo "~$REAL_USER")
export PATH="$REAL_HOME/.pdtm/go/bin:$REAL_HOME/go/bin:$PATH"

############################
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
   --skip-katana           Skip Katana crawl (JS, params extraction)
   --skip-permutations     Skip subdomain permutations (alterx + puredns)
   --perms-limit           Max permutations to resolve (default: 50000)
   --cookie, -ck           Cookie for authenticated recon (e.g., "session=abc123; token=xyz")
   --proxy                 Proxy URL (e.g., http://localhost:8080 for Caido)
   --rate, -c             Requests per second (e.g., -c 5 for 5 req/sec)

${YELLOW}EXAMPLES:${NC}
  $0 example.com
  $0 example.com --skip-nuclei --skip-jsleaks
  $0 example.com --proxy http://localhost:8080
  $0 example.com --proxy http://127.0.0.1:8080 --skip-nuclei
  $0 example.com -c 5
  $0 example.com -c 10 --proxy http://localhost:8080
  $0 example.com --cookie "session=abc123; token=xyz"
  $0 example.com --cookie "session=abc123" --proxy http://localhost:8080

${YELLOW}DESCRIPTION:${NC}
  This script automates the reconnaissance process for a given target domain.
  It performs the following steps in order:
    0. Scope Broadening (ASN/whois discovery)
    1. Subdomain Enumeration (subfinder, assetfinder, amass, chaos)
    2. Live Host Detection + Tech Stack (httpx single pass)
    3. Katana Crawl (deep URL/JS/params discovery)
    3b. Extract API, Secrets, Admin Panels, Debug Endpoints
    4. Mantra JS Secret Scan (API key leak detection)
    4b. Nuclei Recommendations (based on recon data)
    5. Vulnerability Scanning (nuclei)
    6. Subdomain Permutations (alterx + puredns)
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
SKIP_KATANA=false
SKIP_PERMS=false
PERMS_LIMIT=50000
PROXY=""
RATE=""
COOKIE=""

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
    --skip-katana)
      SKIP_KATANA=true
      ;;
    --skip-permutations)
      SKIP_PERMS=true
      ;;
    --perms-limit)
      PERMS_LIMIT="$2"
      shift
      ;;
    --cookie|-ck)
      COOKIE="$2"
      shift
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

if [ -n "$COOKIE" ]; then
  echo -e "${BLUE}[*] Using cookie for authenticated recon${NC}"
fi

############################
# Check Target
############################
outdir=$domain

mkdir -p "$outdir"

############################
# Required Tools
############################
tools=(subfinder assetfinder amass httpx anew alterx puredns chaos asnmap)
[ "$SKIP_NUCLEI" = false ] && tools+=(nuclei notify)
[ "$SKIP_KATANA" = false ] && tools+=(katana)
[ "$SKIP_JSLEAKS" = false ] && [ "$SKIP_KATANA" = false ] && tools+=(mantra)

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
nuclei_out="$outdir/nuclei_results.txt"
mantra_out="$outdir/mantra_results.txt"
resolved="$outdir/resolved_subs.txt"
scope_file="$outdir/broad_scope.txt"
cidr_file="$outdir/cidr_ranges.txt"
ip_file="$outdir/ip_addrs.txt"
done_dir="$outdir/.done"

############################
# 0. Scope Broadening
############################
if [ "$SKIP_SCOPE" = false ]; then
  if [ ! -f "$done_dir/scope.done" ]; then
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
    mkdir -p "$done_dir" && touch "$done_dir/scope.done"
  fi
else
  echo -e "${YELLOW}[*] Skipping scope broadening${NC}"
fi

############################
# 1. Subdomain Enumeration
############################
if [ ! -f "$done_dir/subs.done" ]; then
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
  mkdir -p "$done_dir" && touch "$done_dir/subs.done"
fi

############################
# 2. Live Hosts + Tech Detection (single pass)
############################
if [ ! -f "$done_dir/live.done" ]; then
  echo -e "${BLUE}[*] Checking live hosts + tech detection${NC}"
  httpx_opts=( -silent -td -threads 50 -retries 1 )
  if [ -n "$PROXY" ]; then
    httpx_opts+=( -proxy "$PROXY" )
  fi
  if [ -n "$RATE" ]; then
    httpx_opts+=( -rl "$RATE" )
  fi
  if [ -n "$COOKIE" ]; then
    httpx_opts+=( -H "Cookie: $COOKIE" )
  fi
  tmp_httpx="$outdir/.httpx_combined.tmp"
  cat "$subs" | httpx "${httpx_opts[@]}" | sed 's/\x1b\[[0-9;]*m//g' > "$tmp_httpx" || true

  # Extract live hosts (URL before the tech brackets)
  sed 's/ \[.*$//' "$tmp_httpx" | anew "$live" || true

  # Extract tech info (URL: tech) — only lines where tech was actually detected
  sed 's/^\(https\?:\/\/[^ ]*\) \[\(.*\)\]$/\1: \2/' "$tmp_httpx" | grep -v ': *$' | grep -v '^\S*$' > "$tech_file" || true

  rm -f "$tmp_httpx"

  echo -e "${GREEN}[+] Live hosts: $(wc -l <"$live" 2>/dev/null || echo 0)${NC}"
  echo -e "${GREEN}[+] Tech stack: $(wc -l <"$tech_file" 2>/dev/null || echo 0) hosts${NC}"
  mkdir -p "$done_dir" && touch "$done_dir/live.done" && touch "$done_dir/tech.done"
else
  echo -e "${YELLOW}[*] Skipping live host + tech detection (already done)${NC}"
fi

############################
# 3. Katana Crawl
############################
if [ "$SKIP_KATANA" = false ]; then
  if [ ! -f "$done_dir/katana.done" ]; then
    echo -e "${BLUE}[*] Running katana crawl${NC}"
    katana_opts=(
      -list "$live"
      -d 1                          # depth 1
      -jc -jsluice
      -ef woff,css,svg,png,jpg,gif
      -silent
      -c 5                          # max 5 concurrent fetchers
      -p 10                         # max 10 concurrent host inputs
      -mdp 200                      # max 200 pages per domain
      -iqp                          # ignore different query-param values (dedup)
      -fsu                          # filter similar-looking URLs (e.g. /user/123 vs /user/456)
      -fpt error,captcha,parked     # skip error/captcha/parked pages
      -hrl 10                       # max 10 requests/sec per host
      -ct 10                        # 10s request timeout
      -o "$outdir/katana_urls.txt"
    )
    if [ -n "$PROXY" ]; then
      katana_opts+=( -proxy "$PROXY" )
    fi
    if [ -n "$RATE" ]; then
      katana_opts+=( -rl "$RATE" )
    fi
    if [ -n "$COOKIE" ]; then
      katana_opts+=( -H "Cookie: $COOKIE" )
    fi
    katana "${katana_opts[@]}"
    echo -e "${GREEN}[+] Katana URLs: $(wc -l <"$outdir/katana_urls.txt" 2>/dev/null || echo 0)${NC}"
    mkdir -p "$done_dir" && touch "$done_dir/katana.done"
  fi
else
  echo -e "${YELLOW}[*] Skipping Katana crawl${NC}"
fi

############################
# 3b. Extract JS, API, Secrets, Params from Katana
############################
js="$outdir/jsfiles.txt"
js_all="$outdir/all_js.txt"
if [ -f "$outdir/katana_urls.txt" ] && [ -s "$outdir/katana_urls.txt" ]; then

  echo -e "${YELLOW}[*] Extracting JS files from katana crawl${NC}"
  grep -Ei "\.js($|\?|#)" "$outdir/katana_urls.txt" \
    | sed 's/[?#].*//' \
    | sort -u \
    > "$js_all" || true
  cp "$js_all" "$js" 2>/dev/null || true
  echo -e "${GREEN}[+] JS files: $(wc -l <"$js_all" 2>/dev/null || echo 0)${NC}"

  echo -e "${YELLOW}[*] Extracting API endpoints${NC}"
  grep -Ei "/(api|graphql|rest|soap|v[0-9]+|swagger|openapi|docs|documentation)" "$outdir/katana_urls.txt" \
    | sort -u > "$outdir/api_endpoints.txt" || true
  echo -e "${GREEN}[+] API endpoints: $(wc -l <"$outdir/api_endpoints.txt" 2>/dev/null || echo 0)${NC}"

  echo -e "${YELLOW}[*] Extracting sensitive / secret files${NC}"
  grep -Ei "\.(env|git|htaccess|htpasswd|sql|bak|backup|config|cfg|ini|log|key|pem|crt|p12|jks|keystore|yaml|yml|toml|xml|json|properties|csv|xls|xlsx|doc|docx|ppt|pptx)(\?|$|#)" "$outdir/katana_urls.txt" \
    | sort -u > "$outdir/secret_files.txt" || true
  grep -Ei "(wp-config|\.ssh|\.aws|\.docker|\.env\.|credentials|secret|private|token)" "$outdir/katana_urls.txt" \
    | sort -u >> "$outdir/secret_files.txt" || true
  sort -u -o "$outdir/secret_files.txt" "$outdir/secret_files.txt" || true
  echo -e "${GREEN}[+] Secret files: $(wc -l <"$outdir/secret_files.txt" 2>/dev/null || echo 0)${NC}"

  echo -e "${YELLOW}[*] Extracting admin / dashboard panels${NC}"
  grep -Ei "/(admin|dashboard|panel|manage|console|portal|wp-admin|cpanel|phpmyadmin|adminer|manager)" "$outdir/katana_urls.txt" \
    | sort -u > "$outdir/admin_panels.txt" || true
  echo -e "${GREEN}[+] Admin panels: $(wc -l <"$outdir/admin_panels.txt" 2>/dev/null || echo 0)${NC}"

  echo -e "${YELLOW}[*] Extracting debug / health endpoints${NC}"
  grep -Ei "/(debug|actuator|health|metrics|trace|status|info|server-status|server-info|_debug|phpinfo|elmah|trace.axd)" "$outdir/katana_urls.txt" \
    | sort -u > "$outdir/debug_endpoints.txt" || true
  echo -e "${GREEN}[+] Debug endpoints: $(wc -l <"$outdir/debug_endpoints.txt" 2>/dev/null || echo 0)${NC}"

  echo -e "${YELLOW}[*] Extracting interesting parameters (SSRF/IDOR/redirect)${NC}"
  grep -Ei "[?&](url|redirect|next|return|go|redir|callback|uri|path|file|document|folder|pg|data|load|src|dest|continue|target|link|image|img|ref|site|page|cmd|command|exec|eval|query|search|q|id|uid|user|account|token|key|session|debug|admin|test|env|config)" "$outdir/katana_urls.txt" \
    | sort -u > "$outdir/interesting_params.txt" || true
  echo -e "${GREEN}[+] Interesting params: $(wc -l <"$outdir/interesting_params.txt" 2>/dev/null || echo 0)${NC}"

  echo -e "${YELLOW}[*] Extracting documents & data files${NC}"
  grep -Ei "\.(pdf|csv|xls|xlsx|doc|docx|ppt|pptx|txt|rtf|odt|ods|xml|json|yaml|yml)(\?|$|#)" "$outdir/katana_urls.txt" \
    | sort -u > "$outdir/documents.txt" || true
  echo -e "${GREEN}[+] Documents: $(wc -l <"$outdir/documents.txt" 2>/dev/null || echo 0)${NC}"

  echo -e "${YELLOW}[*] Extracting URLs with query parameters${NC}"
  grep "=" "$outdir/katana_urls.txt" | anew "$outdir/katana_params.txt" || true

else
  echo -e "${YELLOW}[!] No katana URLs to filter${NC}"
  touch "$js_all" "$js"
  touch "$outdir/api_endpoints.txt" "$outdir/secret_files.txt" "$outdir/admin_panels.txt"
  touch "$outdir/debug_endpoints.txt" "$outdir/interesting_params.txt" "$outdir/documents.txt"
  touch "$outdir/katana_params.txt"
fi

############################
# 4. Mantra JS Secret Scan
############################
if [ "$SKIP_JSLEAKS" = false ] && [ ! -f "$done_dir/mantra.done" ]; then
  js_scan_file="$js_all"
  if [ ! -f "$js_scan_file" ] || [ ! -s "$js_scan_file" ]; then
    js_scan_file="$js"
  fi
  if [ -f "$js_scan_file" ] && [ -s "$js_scan_file" ]; then
    js_count=$(wc -l <"$js_scan_file")
    # Cap JS input to 500 files to avoid mantra hanging on huge lists
    if [ "$js_count" -gt 500 ]; then
      echo -e "${YELLOW}[!] $js_count JS files — capping to 500 for mantra${NC}"
      head -500 "$js_scan_file" > "$outdir/_mantra_input.txt"
      js_scan_file="$outdir/_mantra_input.txt"
    fi
    mantra_threads=20
    [ -n "$RATE" ] && mantra_threads="$RATE"
    mantra_opts=( -s -t "$mantra_threads" )
    if [ -n "$COOKIE" ]; then
      mantra_opts+=( -c "$COOKIE" )
    fi
    echo -e "${YELLOW}[*] Running Mantra API key scan on JS files (threads: $mantra_threads)${NC}"
    cat "$js_scan_file" | mantra "${mantra_opts[@]}" | anew "$mantra_out" || true
    rm -f "$outdir/_mantra_input.txt"
    echo -e "${GREEN}[+] Mantra scan complete: $(wc -l <"$mantra_out" 2>/dev/null || echo 0) findings${NC}"
    mkdir -p "$done_dir" && touch "$done_dir/mantra.done"
  fi
fi

############################
# 4b. Nuclei Recommendations (based on recon data)
############################
echo -e "\n${YELLOW}[*] Analyzing recon data for nuclei recommendations...${NC}"
recommendations_file="$outdir/nuclei_recommendations.txt"
: > "$recommendations_file"

tech_recs="" 
admin_recs=""
debug_recs=""
api_recs=""
secret_recs=""
param_recs=""

# Detect tech stack and recommend templates
if [ -f "$tech_file" ] && [ -s "$tech_file" ]; then
  tech_data=$(cat "$tech_file" | tr '[:upper:]' '[:lower:]')
  echo "$tech_data" | grep -qi "apache"   && tech_recs="${tech_recs}  -tags apache\n"
  echo "$tech_data" | grep -qi "nginx"    && tech_recs="${tech_recs}  -tags nginx\n"
  echo "$tech_data" | grep -qi "iis"      && tech_recs="${tech_recs}  -tags iis\n"
  echo "$tech_data" | grep -qi "tomcat"   && tech_recs="${tech_recs}  -tags tomcat\n"
  echo "$tech_data" | grep -qi "php"      && tech_recs="${tech_recs}  -tags php\n"
  echo "$tech_data" | grep -qi "asp"      && tech_recs="${tech_recs}  -tags asp\n"
  echo "$tech_data" | grep -qi "java"     && tech_recs="${tech_recs}  -tags java\n"
  echo "$tech_data" | grep -qi "spring"   && tech_recs="${tech_recs}  -tags spring\n"
  echo "$tech_data" | grep -qi "express"  && tech_recs="${tech_recs}  -tags express\n"
  echo "$tech_data" | grep -qi "django"   && tech_recs="${tech_recs}  -tags django\n"
  echo "$tech_data" | grep -qi "laravel"  && tech_recs="${tech_recs}  -tags laravel\n"
  echo "$tech_data" | grep -qi "wordpress" && tech_recs="${tech_recs}  -tags wordpress\n"
  echo "$tech_data" | grep -qi "drupal"   && tech_recs="${tech_recs}  -tags drupal\n"
  echo "$tech_data" | grep -qi "joomla"   && tech_recs="${tech_recs}  -tags joomla\n"
  echo "$tech_data" | grep -qi "jenkins"  && tech_recs="${tech_recs}  -tags jenkins\n"
  echo "$tech_data" | grep -qi "gitlab"   && tech_recs="${tech_recs}  -tags gitlab\n"
  echo "$tech_data" | grep -qi "grafana"  && tech_recs="${tech_recs}  -tags grafana\n"
  echo "$tech_data" | grep -qi "kibana"   && tech_recs="${tech_recs}  -tags kibana\n"
  echo "$tech_data" | grep -qi "kong"     && tech_recs="${tech_recs}  -tags kong\n"
  echo "$tech_data" | grep -qi "cloudflare" && tech_recs="${tech_recs}  -tags cloudflare\n"
  echo "$tech_data" | grep -qi "akamai"   && tech_recs="${tech_recs}  -tags akamai\n"
  echo "$tech_data" | grep -qi "fastly"   && tech_recs="${tech_recs}  -tags fastly\n"
fi

# Check admin panels
if [ -f "$outdir/admin_panels.txt" ] && [ -s "$outdir/admin_panels.txt" ]; then
  admin_recs="  -tags default-login,admin\n  -tags panel\n"
fi

# Check debug endpoints
if [ -f "$outdir/debug_endpoints.txt" ] && [ -s "$outdir/debug_endpoints.txt" ]; then
  debug_recs="  -tags debug,exposure\n  -tags phpinfo,actuator\n"
fi

# Check API endpoints
if [ -f "$outdir/api_endpoints.txt" ] && [ -s "$outdir/api_endpoints.txt" ]; then
  api_recs="  -tags graphql\n  -tags swagger,openapi\n  -tags api\n"
fi

# Check secret files
if [ -f "$outdir/secret_files.txt" ] && [ -s "$outdir/secret_files.txt" ]; then
  secret_recs="  -tags exposure,config\n  -tags .env,git\n"
fi

# Check interesting params
if [ -f "$outdir/interesting_params.txt" ] && [ -s "$outdir/interesting_params.txt" ]; then
  param_recs="  -tags ssrf\n  -tags redirect\n  -tags lfi\n"
fi

# Check live host count for brute force templates
live_count=0
[ -f "$live" ] && live_count=$(wc -l <"$live" 2>/dev/null || echo 0)

# Build recommendations file
{
  echo "=============================================="
  echo " Nuclei Recommendations for $domain"
  echo " Generated: $(date '+%Y-%m-%d %H:%M')"
  echo "=============================================="
  echo ""

  if [ -n "$tech_recs" ]; then
    echo "## Tech-specific templates (from tech stack)"
    echo "nuclei -l $live -tags <tech> -silent"
    echo -e "$tech_recs"
  fi

  if [ -n "$admin_recs" ]; then
    echo "## Admin panel / default login checks"
    echo "nuclei -l $live -silent"
    echo -e "$admin_recs"
  fi

  if [ -n "$debug_recs" ]; then
    echo "## Debug / info exposure"
    echo "nuclei -l $live -silent"
    echo -e "$debug_recs"
  fi

  if [ -n "$api_recs" ]; then
    echo "## API-specific checks"
    echo "nuclei -l $live -silent"
    echo -e "$api_recs"
  fi

  if [ -n "$secret_recs" ]; then
    echo "## Secret / config file exposure"
    echo "nuclei -l $live -silent"
    echo -e "$secret_recs"
  fi

  if [ -n "$param_recs" ]; then
    echo "## Parameter-based vuln checks (use with param URLs)"
    echo "nuclei -l $outdir/interesting_params.txt -silent"
    echo -e "$param_recs"
  fi

  echo "## Full aggressive scan (all of the above)"
  if [ -n "$COOKIE" ]; then
    echo "nuclei -l $live -severity critical,high,medium -silent -H \"Cookie: $COOKIE\""
  else
    echo "nuclei -l $live -severity critical,high,medium -silent"
  fi
  echo ""
  echo "## Targeted scan on interesting params"
  if [ -f "$outdir/interesting_params.txt" ] && [ -s "$outdir/interesting_params.txt" ]; then
    if [ -n "$COOKIE" ]; then
      echo "nuclei -l $outdir/interesting_params.txt -tags ssrf,redirect,lfi,rce -silent -H \"Cookie: $COOKIE\""
    else
      echo "nuclei -l $outdir/interesting_params.txt -tags ssrf,redirect,lfi,rce -silent"
    fi
  fi
  echo ""
  echo "=============================================="

} > "$recommendations_file"

echo -e "${GREEN}[+] Recommendations saved: $recommendations_file${NC}"
echo -e "${BLUE}[*] === NUCLEI RECOMMENDATIONS ===${NC}"
cat "$recommendations_file"
echo -e "${BLUE}[*] =================================${NC}\n"

############################
# 5. Nuclei Scan
############################
if [ "$SKIP_NUCLEI" = false ]; then
  if [ ! -f "$done_dir/nuclei.done" ]; then
    echo -e "${BLUE}[*] Running nuclei scan${NC}"
    nuclei_opts=( -silent )
    if [ -n "$PROXY" ]; then
      nuclei_opts+=( -proxy "$PROXY" )
    fi
    if [ -n "$RATE" ]; then
      nuclei_opts+=( -rl "$RATE" )
    fi
    if [ -n "$COOKIE" ]; then
      nuclei_opts+=( -H "Cookie: $COOKIE" )
    fi
    nuclei -l "$live" "${nuclei_opts[@]}" -o "$nuclei_out"
    if grep -qiE "critical|high" "$nuclei_out" 2>/dev/null; then
      notify -silent < "$nuclei_out"
    fi
    echo -e "${GREEN}[+] Nuclei findings: $(wc -l <"$nuclei_out")${NC}"
    mkdir -p "$done_dir" && touch "$done_dir/nuclei.done"
  fi
else
  echo -e "${YELLOW}[*] Skipping Nuclei scan${NC}"
fi

############################
# 6. Subdomain Permutations (alterx + puredns)
############################
alt_file="$outdir/alterx_subs.txt"
if [ "$SKIP_PERMS" = true ]; then
  echo -e "${YELLOW}[*] Skipping subdomain permutations${NC}"
  touch "$resolved"
  mkdir -p "$done_dir" && touch "$done_dir/alterx.done"
elif [ ! -f "$done_dir/alterx.done" ]; then
  echo -e "${BLUE}[*] Generating subdomain permutations with alterx${NC}"

  # Use live_hosts if available (much smaller), fall back to full subdomains
  perm_input="$subs"
  if [ -f "$live" ] && [ -s "$live" ]; then
    # Extract hostnames from live_hosts.txt (strip scheme) for permutations
    sed 's|https\?://||;s|/.*||' "$live" | sort -u > "$outdir/_perm_input.txt"
    perm_input="$outdir/_perm_input.txt"
    echo -e "${YELLOW}[*] Using $(wc -l <"$perm_input") live hostnames for permutations (faster)${NC}"
  fi

  src_count=$(wc -l <"$perm_input" 2>/dev/null || echo 0)
  if [ "$src_count" -gt 0 ]; then
    # If source is huge, cap it to avoid massive permutation explosion
    effective_input="$perm_input"
    if [ "$src_count" -gt 5000 ]; then
      echo -e "${YELLOW}[!] $src_count input hosts — capping to 5000 for alterx${NC}"
      shuf -n 5000 "$perm_input" > "$outdir/_perm_capped.txt"
      effective_input="$outdir/_perm_capped.txt"
    fi

    alterx -l "$effective_input" -silent -en 2>/dev/null | head -"$PERMS_LIMIT" > "$alt_file" || true
    rm -f "$outdir/_perm_input.txt" "$outdir/_perm_capped.txt"

    if [ -f "$alt_file" ] && [ -s "$alt_file" ]; then
      perm_count=$(wc -l <"$alt_file")
      echo -e "${GREEN}[+] alterx generated $perm_count permutations${NC}"

      # If permutations exceed the limit, inform user
      if [ "$perm_count" -ge "$PERMS_LIMIT" ]; then
        echo -e "${YELLOW}[!] Hit the --perms-limit of $PERMS_LIMIT. Resolving in batches...${NC}"
      fi

      echo -e "${BLUE}[*] Resolving with puredns${NC}"
      cat "$alt_file" | puredns resolve | anew "$resolved" || true
      echo -e "${GREEN}[+] Resolved $(wc -l <"$resolved" 2>/dev/null || echo 0) new subdomains${NC}"
    else
      echo -e "${YELLOW}[!] alterx generated no permutations${NC}"
      touch "$resolved"
    fi
  else
    echo -e "${YELLOW}[!] No subdomains to permute${NC}"
    touch "$resolved"
  fi
  mkdir -p "$done_dir" && touch "$done_dir/alterx.done"
fi

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
