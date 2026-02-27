#!/usr/bin/env python3
import subprocess
import os

def win_enum():
    """Windows privilege escalation enumeration"""

    print("=" * 60)
    print("Windows Privilege Escalation Enumeration")
    print("=" * 60)

    commands = [
        ("System Info", "systeminfo"),
        ("User Info", "whoami /all"),
        ("Sudo Groups", "whoami /groups"),
        ("Network Config", "ipconfig /all"),
        ("ARP Table", "arp -a"),
        ("Running Services", "net start"),
        ("Scheduled Tasks", "schtasks /query /fo LIST /v"),
        ("Installed Software", "wmic product get name,version"),
        ("Process List", "tasklist /svc"),
        ("AlwaysInstallElevated", "reg query HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\Installer /v AlwaysInstallElevated"),
    ]

    for name, cmd in commands:
        print(f"\n[+] {name}:")
        print("-" * 40)
        try:
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=10)
            print(result.stdout[:2000])  # Limit output
        except Exception as e:
            print(f"Error: {e}")

if __name__ == "__main__":
    win_enum()