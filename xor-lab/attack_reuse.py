#!/usr/bin/env python3
# attack_reuse.py - simple crib-drag helper
from binascii import unhexlify, hexlify
import sys

PRINTABLE = set(range(0x20, 0x7f))

def xor_bytes(a,b):
    return bytes(x ^ y for x,y in zip(a, b))

def is_printable(bs):
    return all(b in PRINTABLE for b in bs)

def crib_drag(c1, c2, crib_bytes):
    n = min(len(c1), len(c2))
    x = xor_bytes(c1[:n], c2[:n])
    res = []
    for pos in range(0, n - len(crib_bytes) + 1):
        seg = x[pos:pos+len(crib_bytes)]
        p_candidate = bytes(a ^ b for a,b in zip(seg, crib_bytes))
        if is_printable(p_candidate):
            res.append((pos, p_candidate))
    return res

def main():
    if len(sys.argv) < 3:
        print("Usage: attack_reuse.py c1.hex c2.hex [crib]")
        return
    c1 = unhexlify(open(sys.argv[1],"rb").read().strip())
    c2 = unhexlify(open(sys.argv[2],"rb").read().strip())
    minlen = min(len(c1), len(c2))
    c1 = c1[:minlen]; c2 = c2[:minlen]
    x = xor_bytes(c1, c2)
    print("c1 xor c2 (hex):", hexlify(x).decode())
    if len(sys.argv) >= 4:
        crib = sys.argv[3].encode()
        res = crib_drag(c1, c2, crib)
        if not res:
            print("No printable candidates found for crib at any position.")
        else:
            print("Candidates (pos, plaintext_fragment):")
            for pos, frag in res:
                print(pos, frag.decode(errors='replace'))
    else:
        # Fix quoting to avoid syntax errors when printing guidance
        print('No crib provided. Try: python3 attack_reuse.py c1.hex c2.hex " the "')
        print("This tool prints c1 xor c2 and can crib-drag when given a crib word.")

if __name__ == '__main__':
    main()
