#!/usr/bin/env python3
# sender.py — send lua scripts to the injected payload from termux
# usage: python sender.py script.lua

import sys, os, socket, time

SOCK = "/data/local/tmp/executor.sock"

def send(src):
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    for _ in range(10):
        try:
            s.connect(SOCK)
            break
        except (FileNotFoundError, ConnectionRefusedError):
            time.sleep(0.5)
    else:
        print("[-] cannot connect to", SOCK)
        print("    is the payload injected? is roblox running?")
        sys.exit(1)

    s.sendall(src.encode())
    s.close()
    print("[+] sent", len(src), "bytes")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("usage: python sender.py <script.lua>")
        sys.exit(1)

    with open(sys.argv[1]) as f:
        src = f.read()

    send(src)
