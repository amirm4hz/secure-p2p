#include "crypto_utils.h"
#include "peer.h"

#include <stdio.h>
#include <string.h>
#include <openssl/rand.h>
#include <openssl/evp.h>
#include <openssl/sha.h>

/*
 * RFC 3526 Group 14 — 2048-bit MODP prime (same as Python implementation).
 * Both peers use identical p and g so the handshake is compatible across
 * the C and Python implementations.
 */
static const char *DH_PRIME_HEX =
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
    "29024E088A67CC74020BBEA63B139B22514A08798E3404DD"
    "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"
    "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
    "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D"
    "C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F"
    "83655D23DCA3AD961C62F356208552BB9ED529077096966D"
    "670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B"
    "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9"
    "DE2BCBF6955817183995497CEA956AE515D2261898FA0510"
    "15728E5A8AACAA68FFFFFFFFFFFFFFFF";

static const int DH_GENERATOR = 2;


/* ── DH context lifecycle ─────────────────────────────────────────────────── */

int dh_init(dh_ctx_t *ctx) {
    ctx->bn_ctx = BN_CTX_new();
    if (!ctx->bn_ctx) return -1;

    /* Allocate 256 bytes (2048 bits) of cryptographically random data */
    uint8_t rand_buf[DH_KEY_BYTES];
    if (RAND_bytes(rand_buf, DH_KEY_BYTES) != 1) {
        BN_CTX_free(ctx->bn_ctx);
        return -1;
    }

    /* Convert random bytes to a BIGNUM private key */
    ctx->private_key = BN_bin2bn(rand_buf, DH_KEY_BYTES, NULL);
    if (!ctx->private_key) {
        BN_CTX_free(ctx->bn_ctx);
        return -1;
    }

    /*
     * Clamp private key to range [2, p-2].
     * We do this by: private_key = (private_key mod (p-2)) + 2
     * Same logic as the Python implementation.
     */
    BIGNUM *p      = BN_new();
    BIGNUM *p_min2 = BN_new();
    BIGNUM *two    = BN_new();

    BN_hex2bn(&p, DH_PRIME_HEX);
    BN_copy(p_min2, p);
    BN_sub_word(p_min2, 2);
    BN_set_word(two, 2);

    BN_mod(ctx->private_key, ctx->private_key, p_min2, ctx->bn_ctx);
    BN_add(ctx->private_key, ctx->private_key, two);

    BN_free(p);
    BN_free(p_min2);
    BN_free(two);

    /* Clear the random buffer from stack memory */
    memset(rand_buf, 0, sizeof(rand_buf));
    return 0;
}

void dh_free(dh_ctx_t *ctx) {
    if (ctx->private_key) {
        BN_clear_free(ctx->private_key);  /* BN_clear_free zeroes memory first */
        ctx->private_key = NULL;
    }
    if (ctx->bn_ctx) {
        BN_CTX_free(ctx->bn_ctx);
        ctx->bn_ctx = NULL;
    }
}


/* ── DH public key computation ────────────────────────────────────────────── */

int dh_get_public_key(dh_ctx_t *ctx, uint8_t out_buf[DH_KEY_BYTES]) {
    /*
     * public_key = g^private_key mod p
     *
     * BN_mod_exp() uses the Montgomery reduction algorithm for fast
     * modular exponentiation — O(log e) multiplications, same as
     * Python's built-in pow(g, e, p).
     */
    BIGNUM *g   = BN_new();
    BIGNUM *p   = BN_new();
    BIGNUM *pub = BN_new();

    BN_set_word(g, DH_GENERATOR);
    BN_hex2bn(&p, DH_PRIME_HEX);

    if (BN_mod_exp(pub, g, ctx->private_key, p, ctx->bn_ctx) != 1) {
        BN_free(g); BN_free(p); BN_free(pub);
        return -1;
    }

    /* Serialise to fixed DH_KEY_BYTES bytes, big-endian, zero-padded */
    memset(out_buf, 0, DH_KEY_BYTES);
    int num_bytes = BN_num_bytes(pub);
    BN_bn2bin(pub, out_buf + (DH_KEY_BYTES - num_bytes));

    BN_free(g); BN_free(p); BN_free(pub);
    return 0;
}


/* ── DH shared secret computation ────────────────────────────────────────── */

int dh_compute_shared_secret(dh_ctx_t *ctx,
                              const uint8_t their_pub[DH_KEY_BYTES],
                              uint8_t out_buf[DH_KEY_BYTES]) {
    /*
     * shared_secret = their_public_key^our_private_key mod p
     *               = g^(their_private * our_private) mod p
     *
     * Both peers compute the same value because multiplication is
     * commutative — this is the foundation of Diffie-Hellman.
     */
    BIGNUM *their_pub_bn = BN_bin2bn(their_pub, DH_KEY_BYTES, NULL);
    BIGNUM *p            = BN_new();
    BIGNUM *secret       = BN_new();

    BN_hex2bn(&p, DH_PRIME_HEX);

    if (BN_mod_exp(secret, their_pub_bn, ctx->private_key, p, ctx->bn_ctx) != 1) {
        BN_free(their_pub_bn); BN_free(p); BN_free(secret);
        return -1;
    }

    memset(out_buf, 0, DH_KEY_BYTES);
    int num_bytes = BN_num_bytes(secret);
    BN_bn2bin(secret, out_buf + (DH_KEY_BYTES - num_bytes));

    BN_free(their_pub_bn); BN_free(p); BN_free(secret);
    return 0;
}


/* ── AES key derivation ───────────────────────────────────────────────────── */

int dh_derive_aes_key(const uint8_t secret[DH_KEY_BYTES],
                       uint8_t aes_key_out[AES_KEY_BYTES]) {
    /*
     * AES key = SHA-256(shared_secret)
     *
     * SHA-256 maps the 2048-bit shared secret to a uniform 256-bit key.
     * This removes mathematical structure from the raw DH output.
     * Same operation as the Python implementation — keys are compatible.
     */
    SHA256(secret, DH_KEY_BYTES, aes_key_out);
    return 0;
}


/* ── Handshake ────────────────────────────────────────────────────────────── */

int perform_handshake_sender(int sock, uint8_t aes_key_out[AES_KEY_BYTES]) {
    dh_ctx_t dh;
    if (dh_init(&dh) != 0) return -1;

    uint8_t our_pub[DH_KEY_BYTES];
    uint8_t their_pub[DH_KEY_BYTES];
    uint8_t secret[DH_KEY_BYTES];

    /* Step 1: Send our public key */
    dh_get_public_key(&dh, our_pub);
    printf("[*] DH: Sending public key to receiver...\n");
    if (send_bytes(sock, our_pub, DH_KEY_BYTES) != 0) {
        dh_free(&dh); return -1;
    }

    /* Step 2: Receive their public key */
    uint8_t *recv_buf = NULL;
    ssize_t  recv_len = recv_bytes(sock, &recv_buf);
    if (recv_len != DH_KEY_BYTES) {
        free(recv_buf); dh_free(&dh); return -1;
    }
    memcpy(their_pub, recv_buf, DH_KEY_BYTES);
    free(recv_buf);
    printf("[*] DH: Received receiver's public key\n");

    /* Step 3: Compute shared secret */
    dh_compute_shared_secret(&dh, their_pub, secret);
    printf("[*] DH: Shared secret computed\n");

    /* Step 4: Derive AES key */
    dh_derive_aes_key(secret, aes_key_out);

    /* Print first 8 bytes of key as hex for verification */
    printf("[+] DH: AES-256 key derived — ");
    for (int i = 0; i < 8; i++) printf("%02x", aes_key_out[i]);
    printf("... (first 8 bytes shown)\n");

    memset(secret, 0, sizeof(secret));  /* Clear secret from stack */
    dh_free(&dh);
    return 0;
}

int perform_handshake_receiver(int sock, uint8_t aes_key_out[AES_KEY_BYTES]) {
    dh_ctx_t dh;
    if (dh_init(&dh) != 0) return -1;

    uint8_t our_pub[DH_KEY_BYTES];
    uint8_t their_pub[DH_KEY_BYTES];
    uint8_t secret[DH_KEY_BYTES];

    /* Step 1: Receive sender's public key */
    uint8_t *recv_buf = NULL;
    ssize_t  recv_len = recv_bytes(sock, &recv_buf);
    if (recv_len != DH_KEY_BYTES) {
        free(recv_buf); dh_free(&dh); return -1;
    }
    memcpy(their_pub, recv_buf, DH_KEY_BYTES);
    free(recv_buf);
    printf("[*] DH: Received sender's public key\n");

    /* Step 2: Send our public key */
    dh_get_public_key(&dh, our_pub);
    printf("[*] DH: Sending public key to sender...\n");
    if (send_bytes(sock, our_pub, DH_KEY_BYTES) != 0) {
        dh_free(&dh); return -1;
    }

    /* Step 3: Compute shared secret */
    dh_compute_shared_secret(&dh, their_pub, secret);
    printf("[*] DH: Shared secret computed\n");

    /* Step 4: Derive AES key */
    dh_derive_aes_key(secret, aes_key_out);

    printf("[+] DH: AES-256 key derived — ");
    for (int i = 0; i < 8; i++) printf("%02x", aes_key_out[i]);
    printf("... (first 8 bytes shown)\n");

    memset(secret, 0, sizeof(secret));
    dh_free(&dh);
    return 0;
}


/* ── AES-256-CBC encrypt ──────────────────────────────────────────────────── */

ssize_t aes_encrypt(const uint8_t *plaintext, size_t pt_len,
                    const uint8_t key[AES_KEY_BYTES],
                    uint8_t **out_buf) {
    /*
     * Wire format: [16-byte random IV][ciphertext with PKCS#7 padding]
     *
     * The IV is generated fresh for every call using OpenSSL's CSPRNG.
     * EVP_EncryptFinal_ex handles PKCS#7 padding automatically —
     * same padding scheme as pycryptodome in the Python implementation,
     * so C-encrypted chunks can be decrypted by the Python peer.
     */
    uint8_t iv[AES_IV_BYTES];
    if (RAND_bytes(iv, AES_IV_BYTES) != 1) return -1;

    /* Ciphertext is at most plaintext + one full padding block */
    size_t   max_ct = pt_len + AES_IV_BYTES + 16;
    uint8_t *buf    = malloc(max_ct);
    if (!buf) return -1;

    /* Prepend IV */
    memcpy(buf, iv, AES_IV_BYTES);

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) { free(buf); return -1; }

    int out_len1 = 0, out_len2 = 0;
    EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv);
    EVP_EncryptUpdate(ctx, buf + AES_IV_BYTES, &out_len1, plaintext, (int)pt_len);
    EVP_EncryptFinal_ex(ctx, buf + AES_IV_BYTES + out_len1, &out_len2);
    EVP_CIPHER_CTX_free(ctx);

    ssize_t total = AES_IV_BYTES + out_len1 + out_len2;
    *out_buf = buf;
    return total;
}


/* ── AES-256-CBC decrypt ──────────────────────────────────────────────────── */

ssize_t aes_decrypt(const uint8_t *ciphertext, size_t ct_len,
                    const uint8_t key[AES_KEY_BYTES],
                    uint8_t **out_buf) {
    if (ct_len < AES_IV_BYTES) return -1;

    /* Split IV from ciphertext */
    const uint8_t *iv         = ciphertext;
    const uint8_t *ct         = ciphertext + AES_IV_BYTES;
    size_t         ct_data_len = ct_len - AES_IV_BYTES;

    uint8_t *buf = malloc(ct_data_len);
    if (!buf) return -1;

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) { free(buf); return -1; }

    int out_len1 = 0, out_len2 = 0;
    EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv);
    EVP_DecryptUpdate(ctx, buf, &out_len1, ct, (int)ct_data_len);

    if (EVP_DecryptFinal_ex(ctx, buf + out_len1, &out_len2) != 1) {
        /* Padding validation failed — data may be corrupted or tampered */
        EVP_CIPHER_CTX_free(ctx);
        free(buf);
        return -1;
    }

    EVP_CIPHER_CTX_free(ctx);
    *out_buf = buf;
    return out_len1 + out_len2;
}