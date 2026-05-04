#include "integrity.h"
#include <stdio.h>
#include <string.h>
#include <openssl/evp.h>

#define HASH_CHUNK 65536

int hash_file(const char *filepath, uint8_t digest[SHA256_BYTES]) {
    FILE *f = fopen(filepath, "rb");
    if (!f) {
        perror("[!] hash_file: fopen");
        return -1;
    }

    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (!ctx) { fclose(f); return -1; }

    if (EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) != 1) {
        EVP_MD_CTX_free(ctx); fclose(f); return -1;
    }

    uint8_t buf[HASH_CHUNK];
    size_t  n;
    while ((n = fread(buf, 1, sizeof(buf), f)) > 0) {
        if (EVP_DigestUpdate(ctx, buf, n) != 1) {
            EVP_MD_CTX_free(ctx); fclose(f); return -1;
        }
    }

    unsigned int dlen = SHA256_BYTES;
    EVP_DigestFinal_ex(ctx, digest, &dlen);
    EVP_MD_CTX_free(ctx);
    fclose(f);
    return 0;
}

int verify_hash(const uint8_t expected[SHA256_BYTES],
                const uint8_t actual[SHA256_BYTES]) {
    /*
     * Constant-time comparison — XOR each byte pair and OR into diff.
     * If any byte differs, diff becomes non-zero.
     * This takes the same amount of time regardless of where the first
     * difference occurs, preventing timing side-channel attacks.
     */
    int diff = 0;
    for (int i = 0; i < SHA256_BYTES; i++) {
        diff |= expected[i] ^ actual[i];
    }
    return (diff == 0) ? 0 : -1;
}

void format_hash(const uint8_t digest[SHA256_BYTES], char out[65]) {
    for (int i = 0; i < SHA256_BYTES; i++) {
        snprintf(out + i * 2, 3, "%02x", digest[i]);
    }
    out[64] = '\0';
}