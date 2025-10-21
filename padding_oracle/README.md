# Padding‑Oracle

## Overview
- `victim` — local process that validates AES‑CBC PKCS#7 padding and returns only `OK` or `ERR`.
- `gen_target` — generates a random IV and ciphertext (`target.hex`) for a fixed hidden message using the same secret key as `victim`.
- `attacker_skeleton.c` — You need to implement a CBC padding‑oracle attack *client* that repeatedly calls `victim` on modified ciphertexts to recover the plaintext of `target.hex`.
- `Makefile` — build targets.

**Language/Libs**: C + OpenSSL libcrypto (`-lcrypto`).  


## Build
```bash
make
```
This builds:
- `victim`
- `gen_target`
- `attacker` (compiles the skeleton so it runs, but core attack is TODO)

## Usage
1) Generate the target:
```bash
./gen_target > target.hex
```
2) Quick check of the oracle (returns 0 on valid padding, 1 on invalid):
```bash
# Query with the original ciphertext (usually valid padding):
./victim < target.hex && echo "valid" || echo "invalid"
```
3) Complete `attacker_skeleton.c` (look for `TODO:` marks) and then run:
```bash
./attacker target.hex
```
Your attacker should print the recovered plaintext.

---

### Advanced options (optional, for instructors)
- Flip `#define ORACLE_MODE 1` to `2` in `victim.c` to simulate a timing‑oracle (same message but ~5ms jitter on one branch). You measure with multiple samples.
- Change `HIDDEN_MESSAGE` to rotate challenges (keep same key).
