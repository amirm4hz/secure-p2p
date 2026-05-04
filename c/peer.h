#ifndef PEER_H
#define PEER_H

#include <stdint.h>
#include <stdlib.h>
#include <sys/types.h>

/* ── Constants ────────────────────────────────────────────────────────────── */

#define DEFAULT_PORT  9999
#define CHUNK_SIZE    65536   /* 64 KB per chunk — matches Python implementation */
#define HEADER_SIZE   8       /* 8-byte big-endian length prefix */

/* ── Socket helpers ───────────────────────────────────────────────────────── */

/*
 * send_bytes() — send length-prefixed bytes over a connected socket.
 *
 * Wire format: [8-byte big-endian uint64 length][data bytes]
 * Uses send() in a loop to guarantee all bytes are written even if the
 * kernel buffers only part of the data in one call.
 *
 * Returns: 0 on success, -1 on error.
 */
int send_bytes(int sock, const uint8_t *data, size_t len);

/*
 * recv_bytes() — receive one complete length-prefixed message.
 *
 * Reads the 8-byte header to determine message length, then reads
 * exactly that many bytes. Allocates a buffer on the heap — caller
 * is responsible for calling free() on *out_buf.
 *
 * Returns: number of bytes received on success, -1 on error.
 */
ssize_t recv_bytes(int sock, uint8_t **out_buf);

/*
 * recv_exact() — read exactly n bytes from sock, looping if necessary.
 *
 * TCP may deliver fewer bytes than requested in a single recv() call.
 * This function loops until exactly n bytes have been read.
 *
 * Returns: 0 on success, -1 if the connection closed prematurely.
 */
int recv_exact(int sock, uint8_t *buf, size_t n);

#endif /* PEER_H */