#!/usr/bin/env python3
import requests
import sys
from urllib.parse import urljoin

def directory_enum(target_url, wordlist):
    """Enumerate directories using wordlist"""
    found = []

    with open(wordlist, 'r') as f:
        words = f.read().splitlines()

    for word in words:
        url = urljoin(target_url, word)
        try:
            r = requests.get(url, timeout=5, allow_redirects=False)
            if r.status_code != 404:
                print(f"[{r.status_code}] {url}")
                found.append(url)
        except requests.RequestException:
            pass

    return found

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python3 enum.py <url> <wordlist>")
        sys.exit(1)

    directory_enum(sys.argv[1], sys.argv[2])