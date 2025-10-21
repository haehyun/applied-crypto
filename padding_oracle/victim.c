// victim.c - Local padding oracle (AES-128-CBC, PKCS#7).
// Prints "OK\n" for valid padding, "ERR\n" for invalid. Exit 0 on OK, 1 on ERR.
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>
#include <openssl/evp.h>

#define KEY_LEN 16
#define BLK 16
#define ORACLE_MODE 1
// ORACLE_MODE 1: plain OK/ERR branch
// ORACLE_MODE 2: same, but adds small timing jitter on one path (optional)

// Fixed key (do not change across victim/gen_target to keep consistent).
static const unsigned char FIXED_KEY[KEY_LEN] = {
    0x60,0x3d,0xeb,0x10,0x15,0xca,0x71,0xbe,0x2b,0x73,0xae,0xf0,0x85,0x7d,0x77,0x81
};

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

static void jitter(void) {
#if ORACLE_MODE == 2
    // ~5ms busy-wait to simulate a timing side-channel branch
    volatile unsigned long x = 0;
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    unsigned long start = ts.tv_nsec;
    while (1) {
        clock_gettime(CLOCK_MONOTONIC, &ts);
        if ((ts.tv_nsec - start + 1000000000UL) % 1000000000UL > 5 * 1000000UL) break;
        x += ts.tv_nsec;
    }
#endif
    (void)0;
}

int main(void) {
    // Read a single line of hex(IV||C) from stdin
    char *line = NULL;
    size_t cap = 0;
    ssize_t m = getline(&line, &cap, stdin);
    if (m <= 0) { fprintf(stderr, "ERR\n"); free(line); return 1; }
    // strip newline
    if (line[m-1] == '\n') line[m-1] = '\0';

    size_t max = 1<<20;
    unsigned char *buf = malloc(max);
    if (!buf) { fprintf(stderr, "ERR\n"); free(line); return 1; }
    int blen = hex2bin(line, buf, max);
    free(line);
    if (blen < 0 || blen < BLK*2 || blen % BLK != 0) { printf("ERR\n"); free(buf); return 1; }

    const unsigned char *iv = buf;
    const unsigned char *ct = buf + BLK;
    int clen = blen - BLK;

    int ret = 1; // default: invalid

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) { printf("ERR\n"); free(buf); return 1; }
    int outl=0, tot=0;
    unsigned char *pt = malloc(clen);
    if (!pt) { printf("ERR\n"); EVP_CIPHER_CTX_free(ctx); free(buf); return 1; }

    if (EVP_DecryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, FIXED_KEY, iv) == 1) {
        if (EVP_DecryptUpdate(ctx, pt, &outl, ct, clen) == 1) {
            tot = outl;
            int finl = 0;
            // If padding is wrong, this will return 0.
            int ok = EVP_DecryptFinal_ex(ctx, pt + tot, &finl);
            jitter(); // optional branch timing jitter
            if (ok == 1) {
                tot += finl;
                (void)tot; // we never print plaintext
                printf("OK\n");
                ret = 0;
            } else {
                printf("ERR\n");
                ret = 1;
            }
        } else {
            printf("ERR\n");
            ret = 1;
        }
    } else {
        printf("ERR\n");
        ret = 1;
    }

    EVP_CIPHER_CTX_free(ctx);
    free(pt);
    free(buf);
    return ret;
}
