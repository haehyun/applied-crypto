// attacker_skeleton.c - You need to complete the CBC padding-oracle attack.
// This file provides I/O helpers and an oracle runner. Fill the TODOs.
// DO NOT attempt direct decryption: only use victim's OK/ERR result.
//
// Compile: part of `make`
// Run:     ./attacker target.hex
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#define BLK 16

static int hex2bin(const char* hex, unsigned char* out, size_t outcap) {
    size_t n = strlen(hex);
    if (n % 2) return -1;
    size_t bytes = n / 2;
    if (bytes > outcap) return -1;
    for (size_t i = 0; i < bytes; i++) {
        unsigned int x;
        if (sscanf(hex + 2*i, "%2x", &x) != 1) return -1;
        out[i] = (unsigned char)x;
    }
    return (int)bytes;
}

static char* bin2hex_dup(const unsigned char* in, size_t len) {
    char* s = (char*)malloc(len*2 + 2);
    for (size_t i = 0; i < len; i++) sprintf(s + 2*i, "%02x", in[i]);
    s[len*2] = '\n'; s[len*2+1] = '\0';
    return s;
}

// Invoke the oracle: run "./victim" with hex(IV||C*) on stdin.
// Returns 1 if oracle says OK, 0 otherwise.
static int query_oracle(const unsigned char* buf, size_t len) {
    int ok = 0;
    char* hex = bin2hex_dup(buf, len);
    FILE* fp = popen("./victim", "w");
    if (!fp) { free(hex); return 0; }
    fwrite(hex, 1, strlen(hex), fp);
    int rc = pclose(fp);
    free(hex);
    // victim exits 0 on OK (valid padding), non-zero on ERR
    ok = (rc == 0);
    return ok;
}

// Strip PKCS#7 padding in-place; returns new length or -1 on error.
static int unpad(unsigned char* p, int len) {
    if (len <= 0 || len % BLK != 0) return -1;
    int pad = p[len-1];
    if (pad <= 0 || pad > BLK) return -1;
    for (int i = 0; i < pad; i++) {
        if (p[len-1-i] != (unsigned char)pad) return -1;
    }
    return len - pad;
}

int main(int argc, char** argv) {
    if (argc != 2) {
        fprintf(stderr, "Usage: %s target.hex\n", argv[0]);
        return 1;
    }
    // Read target hex
    FILE* f = fopen(argv[1], "rb");
    if (!f) { perror("open"); return 1; }
    fseek(f, 0, SEEK_END);
    long sz = ftell(f);
    fseek(f, 0, SEEK_SET);
    char* hex = (char*)malloc(sz+1);
    fread(hex, 1, sz, f);
    hex[sz] = 0;
    fclose(f);

    unsigned char buf[1<<20];
    int blen = hex2bin(hex, buf, sizeof(buf));
    free(hex);
    if (blen < 0 || blen % BLK != 0 || blen < 2*BLK) {
        fprintf(stderr, "bad input\n");
        return 1;
    }

    // Split into blocks: [IV][C1][C2]...[Ck]
    int blocks = blen / BLK;
    // Output plaintext buffer
    unsigned char* P = (unsigned char*)calloc(blen, 1);

    // === TODO: implement CBC padding‑oracle core ===
    // For i = 1..k (block index; skip IV which is block 0):
    //   Recover P_i by crafting a fake prefix block D and querying the oracle on D||C_i.
    //   Use standard byte‑wise search from pad=1 to 16, updating D bytes to enforce pad value.
    //   Store recovered bytes into P at the correct offset.
    // Hints:
    //   - Work on a local "probe" buffer: [D][C_i].
    //   - Maintain an array "known" for bytes already recovered in the block.
    //   - Be careful with edge cases where a guess accidentally yields a higher‑length valid padding.
    //   - When done, concatenate all P_i, then unpad.

    // Placeholder so the skeleton compiles/runs; remove once implemented.
    fprintf(stdout, "[SKEL] Implement the attack; then print recovered plaintext here.\n");

    free(P);
    return 0;
}
