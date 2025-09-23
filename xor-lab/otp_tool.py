#!/usr/bin/env python3
import sys
import secrets
from binascii import hexlify, unhexlify

def genkey(length, out):
    # generate random bytes and write as hex (no newline trimming issues)
    k = secrets.token_bytes(length)
    open(out, "wb").write(hexlify(k))
    print(f"Generated key (hex) -> {out}")

def xor_bytes(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))

def encrypt(key_hex_path, infile, outfile):
    """
    plaintext file (binary) -> write ciphertext as hex
    Usage: encrypt key.hex message.bin out.ct.hex
    """
    key = unhexlify(open(key_hex_path,"rb").read().strip())
    data = open(infile,"rb").read()            # plaintext bytes
    if len(key) < len(data):
        print("ERROR: key shorter than message", file=sys.stderr); sys.exit(1)
    ct = xor_bytes(data, key[:len(data)])      # ciphertext bytes
    open(outfile,"wb").write(hexlify(ct))      # write hex of ciphertext
    print(f"Encrypted -> {outfile}")

def decrypt(key_hex_path, infile_hex, outfile_hex):
    """
    infile_hex: file containing hex ciphertext (as produced by encrypt)
    outfile_hex: write hex of recovered plaintext (so run_tests' unhexlify will work)
    Usage: decrypt key.hex c1.hex p2.hex
    """
    key = unhexlify(open(key_hex_path,"rb").read().strip())
    # read hex ciphertext and convert to bytes
    ct_hex = open(infile_hex,"rb").read().strip()
    try:
        ct = unhexlify(ct_hex)
    except Exception as e:
        print("ERROR: infile_hex does not contain valid hex ciphertext", file=sys.stderr)
        sys.exit(1)
    if len(key) < len(ct):
        print("ERROR: key shorter than ciphertext", file=sys.stderr); sys.exit(1)
    pt = xor_bytes(ct, key[:len(ct)])          # plaintext bytes
    open(outfile_hex,"wb").write(hexlify(pt))  # write hex of plaintext
    print(f"Decrypted (hex) -> {outfile_hex}")

def usage():
    print("Usage: otp_tool.py genkey <len> <out.hex>")
    print("       otp_tool.py encrypt <key.hex> <infile> <out.hex>   # infile = binary/plaintext")
    print("       otp_tool.py decrypt <key.hex> <infile.hex> <out.hex>  # infile.hex = hex ciphertext; out.hex = hex plaintext")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        usage(); sys.exit(1)
    cmd = sys.argv[1]
    if cmd == "genkey":
        if len(sys.argv) != 4: usage(); sys.exit(1)
        n = int(sys.argv[2]); out = sys.argv[3]; genkey(n, out)
    elif cmd == "encrypt":
        if len(sys.argv) != 5: usage(); sys.exit(1)
        _,_,k,infile,out = sys.argv
        encrypt(k,infile,out)
    elif cmd == "decrypt":
        if len(sys.argv) != 5: usage(); sys.exit(1)
        _,_,k,infile,out = sys.argv
        decrypt(k,infile,out)
    else:
        usage()
