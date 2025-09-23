OTP / XOR Lab
========================

Files:
- otp_tool.py       : key gen + encrypt/decrypt (OTP) tool
- demo_reuse.py     : demo script that generates multiple ciphertexts using same key
- attack_reuse.py   : simple crib-drag helper to inspect c1 xor c2 and test a crib
- sample_plains/    : example plaintexts and an example run script
- run_tests.sh      : basic smoke tests 

Usage examples:
1) Generate a 256-byte key:
   python3 otp_tool.py genkey 256 key.hex

2) Encrypt a file:
   python3 otp_tool.py encrypt key.hex sample_plains/p1.txt c1.hex

3) Demo reuse:
   python3 demo_reuse.py key.hex out_ sample_plains/p1.txt sample_plains/p2.txt

4) Attack helper:
   python3 attack_reuse.py out_1.hex out_2.hex " the "


