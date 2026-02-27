#!/usr/bin/env python3
from ldap3 import Server, Connection, ALL, SUBTREE

def enum_ad_users(domain, username, password):
    """Enumerate users from Active Directory"""
    server = Server(domain, get_info=ALL)

    try:
        conn = Connection(server, user=username, password=password, auto_bind=True)

        # Search for all users
        conn.search(
            search_base='dc={}'.format(domain.split('.')[0]),
            search_filter='(&(objectClass=user)(!(objectClass=computer)))',
            search_scope=SUBTREE,
            attributes=['cn', 'mail', 'memberOf', 'sAMAccountName']
        )

        print("\n[*] Found Users:")
        print("-" * 60)
        for entry in conn.entries:
            print(f"User: {entry.sAMAccountName}")
            print(f"  Email: {entry.mail}")
            print(f"  Groups: {entry.memberOf}")
            print()

    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    import sys
    if len(sys.argv) != 4:
        print("Usage: python3 enum_ad.py <domain> <username> <password>")
        sys.exit(1)

    enum_ad_users(sys.argv[1], sys.argv[2], sys.argv[3])