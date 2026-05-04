#include "transfer.h"
#include "peer.h"
#include "integrity.h"
#include "crypto_utils.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <arpa/inet.h>
#include <sys/time.h>
#include <libgen.h>

#ifdef __APPLE__
#include <libkern/OSByteOrder.h>
#define htobe64(x) OSSwapHostToBigInt64(x)
#define be64toh(x) OSSwapBigToHostInt64(x)
#endif

/* ── Internal progress bar ───────────────────────────────────────────────── */

/*
 * print_progress() — draw a simple progress bar on a single terminal line.
 *
 * Uses \r (carriage return) to overwrite the current line each call.
 * Shows: percentage, bar, bytes transferred, speed in MB/s.
 *
 * No external dependencies — just ANSI escape codes and carriage return.
 */
static void print_progress(size_t done, size_t total, double elapsed_sec) {
    if (total == 0) return;

    double pct       = (double)done / (double)total * 100.0;
    double speed_mbs = (elapsed_sec > 0)
                     ? ((double)done / (1024.0 * 1024.0)) / elapsed_sec
                     : 0.0;

    /* Build the bar — 40 characters wide */
    int filled = (int)(pct / 100.0 * 40);
    char bar[41];
    for (int i = 0; i < 40; i++) bar[i] = (i < filled) ? '#' : '-';
    bar[40] = '\0';

    double done_mb  = (double)done  / (1024.0 * 1024.0);
    double total_mb = (double)total / (1024.0 * 1024.0);

    printf("\r  [%s] %5.1f%% | %.2f/%.2f MB | %.1f MB/s ",
           bar, pct, done_mb, total_mb, speed_mbs);
    fflush(stdout);
}

/* ── Elapsed time helper ──────────────────────────────────────────────────── */

static double elapsed_seconds(struct timeval *start) {
    struct timeval now;
    gettimeofday(&now, NULL);
    return (now.tv_sec  - start->tv_sec) +
           (now.tv_usec - start->tv_usec) / 1e6;
}

/* ── Send file ────────────────────────────────────────────────────────────── */

int send_file(int sock, const char *filepath,
              const uint8_t aes_key[AES_KEY_BYTES]) {
    /* ── Open file and get size ──────────────────────────────────────────── */
    FILE *f = fopen(filepath, "rb");
    if (!f) { perror("[!] send_file: fopen"); return -1; }

    fseek(f, 0, SEEK_END);
    long filesize_signed = ftell(f);
    fseek(f, 0, SEEK_SET);
    if (filesize_signed < 0) { fclose(f); return -1; }
    uint64_t filesize = (uint64_t)filesize_signed;

    /* basename() may modify its argument — use a copy */
    char path_copy[4096];
    strncpy(path_copy, filepath, sizeof(path_copy) - 1);
    const char *filename = basename(path_copy);

    /* ── Compute SHA-256 before sending ─────────────────────────────────── */
    uint8_t file_hash[SHA256_BYTES];
    printf("\n[*] Computing SHA-256 of '%s'...\n", filename);
    if (hash_file(filepath, file_hash) != 0) { fclose(f); return -1; }

    char hash_str[65];
    format_hash(file_hash, hash_str);
    printf("[*] SHA-256: %s\n", hash_str);

    /* ── Send encrypted filename ─────────────────────────────────────────── */
    uint8_t *enc_name = NULL;
    ssize_t  enc_name_len = aes_encrypt(
        (const uint8_t *)filename, strlen(filename), aes_key, &enc_name);
    if (enc_name_len < 0) { fclose(f); return -1; }
    send_bytes(sock, enc_name, (size_t)enc_name_len);
    free(enc_name);

    /* ── Send plaintext filesize (big-endian 8 bytes) ────────────────────── */
    uint64_t filesize_be = htobe64(filesize);
    send_bytes(sock, (uint8_t *)&filesize_be, 8);

    printf("\n[*] Sending '%s' (%.2f MB) — encrypted\n\n",
           filename, (double)filesize / (1024.0 * 1024.0));

    /* ── Chunked encrypted send with progress bar ───────────────────────── */
    uint8_t chunk[CHUNK_SIZE];
    size_t  bytes_sent = 0;
    struct timeval start;
    gettimeofday(&start, NULL);

    while (bytes_sent < filesize) {
        size_t to_read = CHUNK_SIZE;
        if (bytes_sent + to_read > filesize)
            to_read = filesize - bytes_sent;

        size_t n = fread(chunk, 1, to_read, f);
        if (n == 0) break;

        uint8_t *enc_chunk = NULL;
        ssize_t  enc_len   = aes_encrypt(chunk, n, aes_key, &enc_chunk);
        if (enc_len < 0) { fclose(f); return -1; }

        send_bytes(sock, enc_chunk, (size_t)enc_len);
        free(enc_chunk);

        bytes_sent += n;
        print_progress(bytes_sent, filesize, elapsed_seconds(&start));
    }

    fclose(f);
    double duration = elapsed_seconds(&start);
    printf("\n");

    /* ── Send integrity hash ─────────────────────────────────────────────── */
    /* Send raw 32 bytes — no length prefix, fixed size */
    size_t total_sent = 0;
    while (total_sent < SHA256_BYTES) {
        ssize_t s = send(sock, file_hash + total_sent,
                         SHA256_BYTES - total_sent, 0);
        if (s <= 0) return -1;
        total_sent += (size_t)s;
    }
    printf("[*] Integrity hash sent\n");

    /* ── Print stats ─────────────────────────────────────────────────────── */
    double speed = (duration > 0)
                 ? ((double)filesize / (1024.0 * 1024.0)) / duration : 0.0;
    printf("[+] Transfer complete\n");
    printf("    %-10s %s\n",     "File:",     filename);
    printf("    %-10s %.2f MB (%llu bytes)\n",
           "Size:", (double)filesize / (1024.0*1024.0),
           (unsigned long long)filesize);
    printf("    %-10s %.2fs\n",  "Duration:", duration);
    printf("    %-10s %.2f MB/s\n", "Speed:", speed);

    return 0;
}


/* ── Receive file ─────────────────────────────────────────────────────────── */

int receive_file(int sock, const uint8_t aes_key[AES_KEY_BYTES],
                 const char *save_dir) {
    /* ── Receive encrypted filename ─────────────────────────────────────── */
    uint8_t *enc_name = NULL;
    ssize_t  enc_name_len = recv_bytes(sock, &enc_name);
    if (enc_name_len < 0) return -1;

    uint8_t *dec_name = NULL;
    ssize_t  dec_name_len = aes_decrypt(enc_name, (size_t)enc_name_len,
                                         aes_key, &dec_name);
    free(enc_name);
    if (dec_name_len < 0) return -1;

    /* Null-terminate the filename */
    char filename[512];
    size_t fname_len = (size_t)dec_name_len < sizeof(filename) - 1
                     ? (size_t)dec_name_len : sizeof(filename) - 1;
    memcpy(filename, dec_name, fname_len);
    filename[fname_len] = '\0';
    free(dec_name);

    /* ── Receive plaintext filesize ─────────────────────────────────────── */
    uint8_t *size_buf = NULL;
    recv_bytes(sock, &size_buf);
    uint64_t filesize = be64toh(*(uint64_t *)size_buf);
    free(size_buf);

    /* Build save path: <save_dir>/received_<filename> */
    char save_path[1024];
    snprintf(save_path, sizeof(save_path), "%s/received_%s", save_dir, filename);

    printf("\n[*] Receiving '%s' (%.2f MB) — decrypting\n\n",
           filename, (double)filesize / (1024.0 * 1024.0));

    /* ── Chunked encrypted receive with progress bar ────────────────────── */
    FILE *out = fopen(save_path, "wb");
    if (!out) { perror("[!] receive_file: fopen"); return -1; }

    size_t bytes_received = 0;
    struct timeval start;
    gettimeofday(&start, NULL);

    while (bytes_received < filesize) {
        uint8_t *enc_chunk = NULL;
        ssize_t  enc_len   = recv_bytes(sock, &enc_chunk);
        if (enc_len < 0) { fclose(out); return -1; }

        uint8_t *chunk  = NULL;
        ssize_t  pt_len = aes_decrypt(enc_chunk, (size_t)enc_len,
                                       aes_key, &chunk);
        free(enc_chunk);
        if (pt_len < 0) { fclose(out); return -1; }

        fwrite(chunk, 1, (size_t)pt_len, out);
        free(chunk);

        bytes_received += (size_t)pt_len;
        print_progress(bytes_received, filesize, elapsed_seconds(&start));
    }

    fclose(out);
    double duration = elapsed_seconds(&start);
    printf("\n");

    /* ── Receive and verify integrity hash ──────────────────────────────── */
    uint8_t expected_hash[SHA256_BYTES];
    if (recv_exact(sock, expected_hash, SHA256_BYTES) != 0) {
        fprintf(stderr, "[!] Failed to receive integrity hash\n");
        return -1;
    }

    printf("[*] Verifying SHA-256 integrity...\n");

    char expected_str[65], actual_str[65];
    format_hash(expected_hash, expected_str);
    printf("[*] Expected : %s\n", expected_str);

    uint8_t actual_hash[SHA256_BYTES];
    if (hash_file(save_path, actual_hash) != 0) return -1;

    format_hash(actual_hash, actual_str);
    printf("[*] Actual   : %s\n", actual_str);

    if (verify_hash(expected_hash, actual_hash) != 0) {
        fprintf(stderr, "[!] Integrity check FAILED — deleting corrupted file\n");
        remove(save_path);
        return -1;
    }

    printf("[+] Integrity verified — file is authentic and complete\n");

    /* ── Print stats ─────────────────────────────────────────────────────── */
    double speed = (duration > 0)
                 ? ((double)filesize / (1024.0 * 1024.0)) / duration : 0.0;
    printf("[+] Transfer complete\n");
    printf("    %-10s %s\n",     "File:",     filename);
    printf("    %-10s %.2f MB (%llu bytes)\n",
           "Size:", (double)filesize / (1024.0*1024.0),
           (unsigned long long)filesize);
    printf("    %-10s %.2fs\n",  "Duration:", duration);
    printf("    %-10s %.2f MB/s\n", "Speed:", speed);
    printf("    %-10s %s\n",     "Saved to:", save_path);

    return 0;
}