#include "peer.h"
#include "crypto_utils.h"
#include "transfer.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <unistd.h>

#ifdef __APPLE__
#include <libkern/OSByteOrder.h>
#define htobe64(x) OSSwapHostToBigInt64(x)
#define be64toh(x) OSSwapBigToHostInt64(x)
#endif

/* ── Low-level socket helpers ─────────────────────────────────────────────── */

int send_bytes(int sock, const uint8_t *data, size_t len) {
    /*
     * Send a length-prefixed message.
     * Protocol: [8-byte big-endian uint64 length][data]
     *
     * send() may transmit fewer bytes than requested if the kernel
     * send buffer is full — we loop until all bytes are sent.
     */
    uint64_t len_be = htobe64((uint64_t)len);
    uint8_t  header[HEADER_SIZE];
    memcpy(header, &len_be, HEADER_SIZE);

    /* Send header */
    size_t sent = 0;
    while (sent < HEADER_SIZE) {
        ssize_t s = send(sock, header + sent, HEADER_SIZE - sent, 0);
        if (s <= 0) return -1;
        sent += (size_t)s;
    }

    /* Send data */
    sent = 0;
    while (sent < len) {
        ssize_t s = send(sock, data + sent, len - sent, 0);
        if (s <= 0) return -1;
        sent += (size_t)s;
    }

    return 0;
}

int recv_exact(int sock, uint8_t *buf, size_t n) {
    /*
     * Read exactly n bytes from sock.
     * TCP may deliver data in smaller chunks than requested — we loop.
     */
    size_t received = 0;
    while (received < n) {
        ssize_t r = recv(sock, buf + received, n - received, 0);
        if (r <= 0) return -1;
        received += (size_t)r;
    }
    return 0;
}

ssize_t recv_bytes(int sock, uint8_t **out_buf) {
    /*
     * Receive one complete length-prefixed message.
     * Allocates a heap buffer — caller must free(*out_buf).
     */
    uint8_t header[HEADER_SIZE];
    if (recv_exact(sock, header, HEADER_SIZE) != 0) return -1;

    uint64_t len_be;
    memcpy(&len_be, header, HEADER_SIZE);
    size_t len = (size_t)be64toh(len_be);

    uint8_t *buf = malloc(len);
    if (!buf) return -1;

    if (recv_exact(sock, buf, len) != 0) {
        free(buf);
        return -1;
    }

    *out_buf = buf;
    return (ssize_t)len;
}


/* ── Receive mode ─────────────────────────────────────────────────────────── */

static void run_receiver(int port) {
    int server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd < 0) { perror("[!] socket"); return; }

    /* SO_REUSEADDR — lets us restart immediately without 'address in use' */
    int opt = 1;
    setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    struct sockaddr_in addr = {0};
    addr.sin_family      = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port        = htons((uint16_t)port);

    if (bind(server_fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("[!] bind"); close(server_fd); return;
    }

    listen(server_fd, 1);
    printf("[*] Listening on 0.0.0.0:%d — waiting for sender...\n", port);

    struct sockaddr_in client_addr;
    socklen_t client_len = sizeof(client_addr);
    int conn = accept(server_fd, (struct sockaddr *)&client_addr, &client_len);
    if (conn < 0) { perror("[!] accept"); close(server_fd); return; }

    char client_ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &client_addr.sin_addr, client_ip, sizeof(client_ip));
    printf("[+] Connection established from %s:%d\n",
           client_ip, ntohs(client_addr.sin_port));

    uint8_t aes_key[AES_KEY_BYTES];
    if (perform_handshake_receiver(conn, aes_key) != 0) {
        fprintf(stderr, "[!] Handshake failed\n");
        close(conn); close(server_fd); return;
    }

    receive_file(conn, aes_key, ".");

    close(conn);
    close(server_fd);
}


/* ── Send mode ────────────────────────────────────────────────────────────── */

static void run_sender(const char *filepath, const char *host, int port) {
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) { perror("[!] socket"); return; }

    /* Resolve hostname to IP */
    struct hostent *he = gethostbyname(host);
    if (!he) {
        fprintf(stderr, "[!] Cannot resolve host: %s\n", host);
        close(sock); return;
    }

    struct sockaddr_in server_addr = {0};
    server_addr.sin_family = AF_INET;
    server_addr.sin_port   = htons((uint16_t)port);
    memcpy(&server_addr.sin_addr, he->h_addr_list[0], (size_t)he->h_length);

    printf("[*] Connecting to %s:%d ...\n", host, port);

    if (connect(sock, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        perror("[!] connect");
        fprintf(stderr, "[!] Is the receiver running on %s:%d?\n", host, port);
        close(sock); return;
    }

    printf("[+] Connected to %s:%d\n", host, port);

    uint8_t aes_key[AES_KEY_BYTES];
    if (perform_handshake_sender(sock, aes_key) != 0) {
        fprintf(stderr, "[!] Handshake failed\n");
        close(sock); return;
    }

    send_file(sock, filepath, aes_key);
    close(sock);
}


/* ── CLI entry point ──────────────────────────────────────────────────────── */

static void print_usage(const char *prog) {
    printf("Usage:\n");
    printf("  Receive: %s receive [--port PORT]\n", prog);
    printf("  Send:    %s send <filepath> <host> [--port PORT]\n\n", prog);
    printf("Examples:\n");
    printf("  %s receive\n", prog);
    printf("  %s receive --port 8888\n", prog);
    printf("  %s send photo.jpg 192.168.1.5\n", prog);
    printf("  %s send photo.jpg 192.168.1.5 --port 8888\n", prog);
}

int main(int argc, char *argv[]) {
    if (argc < 2) { print_usage(argv[0]); return 1; }

    int port = DEFAULT_PORT;

    if (strcmp(argv[1], "receive") == 0) {
        /* Parse optional --port */
        for (int i = 2; i < argc - 1; i++) {
            if (strcmp(argv[i], "--port") == 0) {
                port = atoi(argv[i + 1]);
            }
        }
        run_receiver(port);

    } else if (strcmp(argv[1], "send") == 0) {
        if (argc < 4) { print_usage(argv[0]); return 1; }
        const char *filepath = argv[2];
        const char *host     = argv[3];
        for (int i = 4; i < argc - 1; i++) {
            if (strcmp(argv[i], "--port") == 0) {
                port = atoi(argv[i + 1]);
            }
        }
        run_sender(filepath, host, port);

    } else {
        print_usage(argv[0]);
        return 1;
    }

    return 0;
}