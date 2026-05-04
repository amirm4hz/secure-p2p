#ifndef TRANSFER_H
#define TRANSFER_H

#include <stdint.h>
#include "crypto_utils.h"

/*
 * send_file() — send a file encrypted chunk by chunk with a progress bar.
 * Returns: 0 on success, -1 on error.
 */
int send_file(int sock, const char *filepath,
              const uint8_t aes_key[AES_KEY_BYTES]);

/*
 * receive_file() — receive, decrypt, and integrity-verify a file.
 * save_dir: directory to write received file into (e.g. ".")
 * Returns: 0 on success, -1 on error.
 */
int receive_file(int sock, const uint8_t aes_key[AES_KEY_BYTES],
                 const char *save_dir);

#endif /* TRANSFER_H */