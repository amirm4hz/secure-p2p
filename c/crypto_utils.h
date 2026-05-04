#ifndef CRYPTO_UTILS_H
#define CRYPTO_UTILS_H

#include <stdint.h>
#include <stdlib.h>
#include <openssl/bn.h>

/* ── Sizes ────────────────────────────────────────────────────────────────── */

#define DH_KEY_BYTES  256   /* 2048-bit DH keys serialised to 256 bytes */
#define AES_KEY_BYTES  32   /* AES-256 key = 32 bytes */
#define AES_IV_BYTES   16   /* AES block size = IV size = 16 bytes */

/* ── Diffie-Hellman context ───────────────────────────────────────────────── */

/*
 * dh_ctx_t holds the DH private key and the shared OpenSSL BIGNUM context.
 * Initialise with dh_init(), free with dh_free().
 */
typedef struct {
    BIGNUM *private_key;  /* Our secret random integer — never transmitted */
    BN_CTX *bn_ctx;       /* OpenSSL scratch space for BN operations */
} dh_ctx_t;

/*
 * dh_init() — initialise a DH context with a fresh random private key.
 * Returns: 0 on success, -1 on error.
 */
int dh_init(dh_ctx_t *ctx);

/*
 * dh_free() — release all OpenSSL BIGNUM resources.
 */
void dh_free(dh_ctx_t *ctx);

/*
 * dh_get_public_key() — compute g^private_key mod p.
 * Serialises the result into out_buf (must be DH_KEY_BYTES bytes).
 * Returns: 0 on success, -1 on error.
 */
int dh_get_public_key(dh_ctx_t *ctx, uint8_t out_buf[DH_KEY_BYTES]);

/*
 * dh_compute_shared_secret() — compute their_public_key^private_key mod p.
 * their_pub must be DH_KEY_BYTES bytes (big-endian).
 * Writes the raw shared secret into out_buf (DH_KEY_BYTES bytes).
 * Returns: 0 on success, -1 on error.
 */
int dh_compute_shared_secret(dh_ctx_t *ctx,
                              const uint8_t their_pub[DH_KEY_BYTES],
                              uint8_t out_buf[DH_KEY_BYTES]);

/*
 * dh_derive_aes_key() — SHA-256 hash of shared secret → 32-byte AES key.
 * secret must be DH_KEY_BYTES bytes.
 * Writes 32 bytes into aes_key_out.
 * Returns: 0 on success, -1 on error.
 */
int dh_derive_aes_key(const uint8_t secret[DH_KEY_BYTES],
                       uint8_t aes_key_out[AES_KEY_BYTES]);

/* ── Handshake ────────────────────────────────────────────────────────────── */

/*
 * perform_handshake_sender() — sender side of DH key exchange.
 * Writes 32-byte AES key into aes_key_out.
 * Returns: 0 on success, -1 on error.
 */
int perform_handshake_sender(int sock, uint8_t aes_key_out[AES_KEY_BYTES]);

/*
 * perform_handshake_receiver() — receiver side of DH key exchange.
 * Writes 32-byte AES key into aes_key_out.
 * Returns: 0 on success, -1 on error.
 */
int perform_handshake_receiver(int sock, uint8_t aes_key_out[AES_KEY_BYTES]);

/* ── AES-256-CBC ──────────────────────────────────────────────────────────── */

/*
 * aes_encrypt() — encrypt plaintext with AES-256-CBC.
 *
 * Generates a fresh random IV, prepends it to the ciphertext.
 * Wire format: [16-byte IV][ciphertext with PKCS#7 padding]
 *
 * out_buf is allocated on the heap — caller must free().
 * Returns: ciphertext length (including IV) on success, -1 on error.
 */
ssize_t aes_encrypt(const uint8_t *plaintext, size_t pt_len,
                    const uint8_t key[AES_KEY_BYTES],
                    uint8_t **out_buf);

/*
 * aes_decrypt() — decrypt AES-256-CBC ciphertext produced by aes_encrypt().
 *
 * Splits off the first 16 bytes as IV, decrypts remainder, strips padding.
 * out_buf is allocated on the heap — caller must free().
 * Returns: plaintext length on success, -1 on error.
 */
ssize_t aes_decrypt(const uint8_t *ciphertext, size_t ct_len,
                    const uint8_t key[AES_KEY_BYTES],
                    uint8_t **out_buf);

#endif /* CRYPTO_UTILS_H */