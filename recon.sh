#!/bin/bash

if [ -z "$1" ]; then
    echo "Usage: $0 domain.com"
    exit 1
fi


TARGET=$1
CHAOS=/home/harsh/go/bin/chaos
NUCLEI=/home/harsh/go/bin/nuclei
HTTPX=/home/harsh/go/bin/httpx
EYEWITNESS=/home/harsh/Desktop/EyeWitness/Python/EyeWitness.py
SECRETFINDER=/home/harsh/SecretFinder/SecretFinder.py
LINKFINDER=/home/harsh/LinkFinder/linkfinder.py

echo "[*] Starting reconnaissance for $TARGET"
mkdir -p recon-$TARGET && cd recon-$TARGET || exit 1
mkdir -p javascript_Recon crawl_params nuclei_scan js_files

#=================================================================================================================================================================================================

echo "[*] Subdomain Enumeration"
proxychains subfinder -d "$TARGET" -all -silent | anew subs.txt

#amass enum -passive -d $TARGET | anew subs.txt

echo "[*] assetfinder Enumeration"
proxychains assetfinder -subs-only "$TARGET" | anew subs.txt

echo "[*] Chaos Subdomain enumeration"
proxychains $CHAOS -d "$TARGET" -silent | anew subs.txt

echo "[*] findomain enumeration"
findomain -t "$TARGET" -q | anew subs.txt

cat subs.txt | proxychains $HTTPX -silent -threads 200 | anew alive.txt

#=================================================================

echo "[*] Taking Screenshots with GoWitness"
gowitness scan file -f alive.txt \
  --screenshot-path screenshots \
  --write-db

gowitness report generate \
  --db-uri sqlite://gowitness.sqlite3
#===================================================================================================================================================================================================


echo "[*] JavaScript Recon"

echo "[+] Collecting js files"
cat alive.txt | "$HTTPX" -silent | proxychains katana -d 5 -jc -silent | grep -iE '\.js$' | anew javascript_Recon/js.txt

echo "[+] Extracting Secrets from JS"
cat javascript_Recon/js.txt | "$HTTPX" -silent -sr -srd js_files/
proxychains nuclei -t ~/.local/nuclei-templates/http/exposures -target javascript_Recon/js.txt

echo "[+] LinkFinder on JS Files"
cat javascript_Recon/js.txt | xargs -I@ -P10 bash -c 'python3 "$LINKFINDER" -i @ -o cli 2>/dev/null' > javascript_Recon/linkfinder.txt

echo "[+] SecretFinder Mass Scan"
cat javascript_Recon/js.txt | xargs -I@ -P5 python3 "$SECRETFINDER" -i @ -o cli > javascript_Recon/secretfinder.txt

echo "[+] API Keys from JS"
cat javascript_Recon/js.txt | $HTTPX -silent | $NUCLEI -t http/exposures/tokens/ -silent > javascript_Recon/api_keys.txt

echo "[+] Find API Endpoints in JS"
cat javascript_Recon/js.txt | xargs -I@ curl -s @ | grep -oE "(/api/[^\"\'\`\s\<\>]+|/v[0-9]+/[^\"\'\`\s\<\>]+)" | sort -u

echo "[+] Extract Hardcoded Credentials"
cat javascript_Recon/js.txt | xargs -I@ curl -s @ | grep -iE "(password|passwd|pwd|secret|api_key|apikey|token|auth)" | sort -u

echo "[+] Extracting AWS Keys from JS"
cat javascript_Recon/js.txt | xargs -I@ curl -s @ | grep -oE "(AKIA[0-9A-Z]{16}|ABIA[0-9A-Z]{16}|ACCA[0-9A-Z]{16}|ASIA[0-9A-Z]{16})" | sort -u | anew javascript_Recon/aws_keys.txt

echo "[+] Extracting Google API Keys from JS"
cat javascript_Recon/js.txt | xargs -I@ curl -s @ | grep -oE "AIza[0-9A-Za-z\-_]{35}" | sort -u | anew javascript_Recon/google_api_keys.txt

echo "[+] Extracting Firebase URLs from JS"
cat javascript_Recon/js.txt | xargs -I@ curl -s @ | grep -oE "https://[a-zA-Z0-9-]+\.firebaseio\.com|https://[a-zA-Z0-9-]+\.firebase\.com" | sort -u | anew javascript_Recon/firebase_urls.txt

echo "[+] Extracting S3 Buckets from JS"
cat javascript_Recon/js.txt | xargs -I@ curl -s @ | grep -oE "[a-zA-Z0-9.-]+\.s3\.amazonaws\.com|s3://[a-zA-Z0-9.-]+|s3-[a-zA-Z0-9-]+\.amazonaws\.com/[a-zA-Z0-9.-]+" | sort -u | anew javascript_Recon/s3_from_js.txt

echo "[+] Extracting Internal IPs from JS"
cat javascript_Recon/js.txt | xargs -I@ curl -s @ | grep -oE "(10\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}|172\.(1[6-9]|2[0-9]|3[0-1])\.[0-9]{1,3}\.[0-9]{1,3}|192\.168\.[0-9]{1,3}\.[0-9]{1,3})" | sort -u | anew javascript_Recon/internal_ips.txt

echo "[+] Extracting GitHub Tokens from JS"
cat javascript_Recon/js.txt | xargs -I@ curl -s @ | grep -oE "(ghp_[a-zA-Z0-9]{36}|gho_[a-zA-Z0-9]{36})" > javascript_Recon/github_tokens.txt


echo "[+] Extracting Email addresses from JS"
cat javascript_Recon/js.txt | xargs -I@ curl -s @ | grep -oE "[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}" > javascript_Recon/emails.txt

echo "[+] Extracting Hidden Subdomains from JS"
cat javascript_Recon/js.txt | xargs -I@ curl -s @ | grep -oE "https?://[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}" > javascript_Recon/urls.txt

echo "[+] Extracting GraphQL Endpoints from JS"
cat javascript_Recon/js.txt | xargs -I@ curl -s @ | grep -oE "(graphql|gql|query|mutation)[^\"']*" > javascript_Recon/graphql.txt

echo "[+] Extracting JWT Tokens from JS Files"
cat javascript_Recon/js.txt | xargs -I@ curl -s @ | grep -oE "eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+" > javascript_Recon/jwt.txt

echo "[+] Extracting Discord Webhooks from JS"
cat javascript_Recon/js.txt | xargs -I@ curl -s @ | grep -oE "https://discord\.com/api/webhooks/[0-9]+/[A-Za-z0-9_-]+" > javascript_Recon/discord.txt

echo "[+] Find Hidden Admin Routes in JS"
cat javascript_Recon/js.txt | xargs -I@ curl -s @ | grep -oE "[\"'][/][a-zA-Z0-9_/-]*(admin|dashboard)[a-zA-Z0-9_/-]*" > javascript_Recon/admin_routes.txt

echo "[+] Extracting Slack Webhooks from JS"
cat javascript_Recon/js.txt | xargs -I@ curl -s @ | grep -oE "https://hooks\.slack\.com/services/T[A-Za-z0-9_/]+" > javascript_Recon/slack.txt

#==========================================================i===========================================================================================================================================

echo "[*] Katana Deep Crawl"
cat alive.txt | proxychains katana -d 8 -jc -kf all -aff -ef woff,css,png,svg,jpg,woff2,jpeg,gif,ico -c 50 -p 20 > crawl_params/katana_multi_Deep_crawl.txt

echo "[+] ParamSpider Discovery"
proxychains paramspider -d "$TARGET" -s > crawl_params/params.txt

echo "[+] Extracting Forms"
proxychains katana -u "https://$TARGET" -f qurl -silent | grep "?" | anew crawl_params/forms.txt

echo "[+] Arjun Discovery"
proxychains arjun -i crawl_params/katana_multi_Deep_crawl.txt -oT crawl_params/arjun_params.txt --stable

#=====================================================================================================================================================================================================


#echo "[*] Nuclei Scanning"
#proxychains nuclei -l alive.txt -tags cve,rce,sqli,xss -severity critical,high -o nuclei_scan/tagged_results.txt

echo "[+] Reconnaissance Complete"
