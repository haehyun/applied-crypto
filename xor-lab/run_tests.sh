#!/bin/bash
set -e
PY=python3

echo "[TEST] genkey"
$PY otp_tool.py genkey 64 key.hex
test -s key.hex

echo "[TEST] encrypt/decrypt consistency"
echo "hello world" > p.txt
$PY otp_tool.py encrypt key.hex p.txt c1.hex
$PY otp_tool.py decrypt key.hex c1.hex p2.hex
python3 - <<'PY'
from binascii import unhexlify
p = open('p.txt','rb').read()
r = unhexlify(open('p2.hex','rb').read().strip())
import sys
assert p==r
print("OK")
PY

echo "[TEST] demo_reuse + attack helper output"
$PY demo_reuse.py key.hex out_ p.txt p.txt
$PY attack_reuse.py out_1.hex out_2.hex " "
echo "[ALL TESTS PASSED]"
