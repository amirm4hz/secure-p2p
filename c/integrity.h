#ifndef INTEGRITY_H
#define INTEGRITY_H

#include <stdint.h>
#include <openssl/sha.h>

#define SHA256_BYTES SHA256_DIGEST_LENGTH   /* 32 bytes */

/*
 * hash_file() — compute SHA-256 of a file on disk, writing into digest.
 * Returns: 0 on success, -1 on error.
 */
int hash_file(const char *filepath, uint8_t digest[SHA256_BYTES]);

/*
 * verify_hash() — constant-time comparison of two 32-byte digests.
 * Returns: 0 if equal, -1 if different.
 */
int verify_hash(const uint8_t expected[SHA256_BYTES],
                const uint8_t actual[SHA256_BYTES]);

/*
 * format_hash() — write hex string of digest into out (must be 65 bytes).
 */
void format_hash(const uint8_t digest[SHA256_BYTES], char out[65]);

#endif /* INTEGRITY_H */