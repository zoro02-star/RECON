#!/usr/bin/env python3
import os
import subprocess
import sys

def lin_enum():
    """Linux privilege escalation enumeration"""

    print("=" * 60)
    print("Linux Privilege Escalation Enumeration")
    print("=" * 60)

    # System Info
    print("\n[+] System Information:")
    os.system("uname -a")
    os.system("cat /etc/issue")

    # User Info
    print("\n[+] Current User:")
    os.system("id")
    os.system("whoami")

    # Sudo Permissions
    print("\n[+] Sudo Permissions:")
    os.system("sudo -l 2>/dev/null")

    # SUID Binaries
    print("\n[+] SUID Binaries:")
    os.system("find / -perm -4000 -type f 2>/dev/null")

    # Writable Directories
    print("\n[+] Writable Directories:")
    os.system("find / -writable -type d 2>/dev/null | head -20")

    # Cron Jobs
    print("\n[+] Cron Jobs:")
    os.system("cat /etc/crontab")
    os.system("ls -la /etc/cron.d/")

    # Network Info
    print("\n[+] Network Connections:")
    os.system("netstat -tuln")

    # Processes
    print("\n[+] Running Processes:")
    os.system("ps aux | grep root")

    # Check for exploits
    print("\n[+] Kernel Version Exploits:")
    os.system("cat /proc/version")
    os.system("searchsploit $(uname -r) 2>/dev/null || echo 'searchsploit not installed'")

if __name__ == "__main__":
    lin_enum()