#!/usr/bin/env python3
# demo_reuse.py
from binascii import hexlify, unhexlify
from otp_tool import xor_bytes
import sys

def main():
    if len(sys.argv) < 4:
        print("Usage: demo_reuse.py <key.hex> out_prefix p1.txt p2.txt ...")
        return
    key = unhexlify(open(sys.argv[1],"rb").read().strip())
    out_prefix = sys.argv[2]
    plains = sys.argv[3:]
    for i, p in enumerate(plains, start=1):
        data = open(p,"rb").read()
        if len(key) < len(data):
            print(f"ERROR: key too short for {p}")
            continue
        ct = xor_bytes(data, key[:len(data)])
        out = f"{out_prefix}{i}.hex"
        open(out,"wb").write(hexlify(ct))
        print(f"Wrote {out}")

if __name__ == "__main__":
    main()
