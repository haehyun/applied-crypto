// gen_target.c - produce IV||C (hex) for a hidden message using the same key as victim.
#include <stdio.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

#define BLK 16
#define KEY_LEN 16

static const unsigned char FIXED_KEY[KEY_LEN] = {
    0x60,0x3d,0xeb,0x10,0x15,0xca,0x71,0xbe,0x2b,0x73,0xae,0xf0,0x85,0x7d,0x77,0x81
};

static const unsigned char HIDDEN_MESSAGE[] =
    "FLAG{applied_crypto_padding_oracle_demo_2025}";

static void bin2hex(const unsigned char* in, int len) {
    for (int i = 0; i < len; i++) printf("%02x", in[i]);
    printf("\n");
}

int main(void) {
    unsigned char iv[BLK];
    RAND_bytes(iv, sizeof(iv));

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    unsigned char ct[4096];
    int outl=0, tot=0;

    if (!ctx) return 1;
    if (EVP_EncryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, FIXED_KEY, iv) != 1) return 1;
    if (EVP_EncryptUpdate(ctx, ct, &outl, HIDDEN_MESSAGE, (int)strlen((const char*)HIDDEN_MESSAGE)) != 1) return 1;
    tot = outl;
    if (EVP_EncryptFinal_ex(ctx, ct + tot, &outl) != 1) return 1;
    tot += outl;

    // Output IV||C in hex (single line)
    bin2hex(iv, BLK);
    for (int i = 0; i < tot; i++) printf("%02x", ct[i]);
    printf("\n");

    EVP_CIPHER_CTX_free(ctx);
    return 0;
}
