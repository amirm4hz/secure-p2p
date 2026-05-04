# secure-p2p — Encrypted P2P File Transfer CLI

A command-line tool for encrypted peer-to-peer file transfer implementing a
manual TLS-like handshake from first principles. Built in Python and C with
full cross-language interoperability.

![Python](https://img.shields.io/badge/Python-3.8+-blue)
![C](https://img.shields.io/badge/C-C99-lightgrey)
![OpenSSL](https://img.shields.io/badge/OpenSSL-3.x-green)
![License](https://img.shields.io/badge/License-MIT-yellow)

---

## Features

- **Manual Diffie-Hellman key exchange** — implemented from scratch using RFC 3526
  Group 14 (2048-bit safe prime), with subgroup validation to prevent
  small-subgroup confinement attacks
- **AES-256-CBC encryption** — every chunk encrypted with a fresh random IV;
  PKCS#7 padding with constant-time validation
- **SHA-256 integrity verification** — constant-time hash comparison using
  `hmac.compare_digest` to prevent timing side-channels
- **Transfer progress bar** — live speed (MB/s) and ETA via tqdm (Python)
- **Any file type and size** — chunked transfer with 64KB chunks
- **Cross-language interoperability** — C sender ↔ Python receiver and vice versa
- **Clean CLI** — send mode and receive mode with `--port` flag

---

## How It Works — Protocol Overview

```
SENDER                                        RECEIVER
──────                                        ────────
$ peer send file.mp4 <ip>                    $ peer receive
        │                                             │
        │◄──────── TCP Handshake (port 9999) ────────►│
        │                                             │
        │       ╔══ PHASE 1: Key Exchange ══╗         │
        │       ║                           ║         │
        │──── DH Public Key A ────────────►│║         │
        │◄─── DH Public Key B ─────────────│║         │
        │       ║                           ║         │
        │       ║  shared_secret =          ║         │
        │       ║  B^a mod p = A^b mod p    ║         │
        │       ║  (never sent over wire)   ║         │
        │       ╚═══════════════════════════╝         │
        │                                             │
        │       ╔══ PHASE 2: Key Derivation ══╗       │
        │       ║                              ║      │
        │       ║  AES_key = SHA-256(secret)   ║      │
        │       ║  (both sides, independently) ║      │
        │       ╚══════════════════════════════╝      │
        │                                             │
        │       ╔══ PHASE 3: Encrypted Transfer ══╗   │
        │       ║                                 ║   │
        │──── AES-256-CBC(filename) ─────────────►│   │
        │──── plaintext filesize ────────────────►│   │
        │──── AES-256-CBC(chunk 1) ──────────────►│   │
        │──── AES-256-CBC(chunk 2) ──────────────►│   │
        │──── AES-256-CBC(chunk N) ──────────────►│   │
        │       ╚═════════════════════════════════╝   │
        │                                             │
        │       ╔══ PHASE 4: Integrity Check ══╗      │
        │       ║                              ║      │
        │──── SHA-256(original file) ─────────►│      │
        │       ║  receiver recomputes hash    ║      │
        │       ║  and compares — byte exact   ║      │
        │       ╚══════════════════════════════╝      │
        │                                             │
        │               ✅ Done                       │
```

**Wire format per message:**
```
[8-byte big-endian length][payload bytes]
```
Each encrypted chunk:
```
[8-byte length][16-byte IV][AES-256-CBC ciphertext + PKCS#7 padding]
```

---

## Implementations

| Feature                  | Python                          | C                          |
|--------------------------|---------------------------------|----------------------------|
| Sockets                  | `socket` stdlib                 | POSIX `sys/socket.h`       |
| DH key exchange          | Pure Python `pow(g, e, p)`      | OpenSSL `BN_mod_exp`       |
| AES-256-CBC              | `pycryptodome`                  | OpenSSL `EVP_*`            |
| SHA-256                  | `hashlib`                       | OpenSSL `EVP_DigestInit`   |
| Progress bar             | `tqdm`                          | Custom ANSI `\r` bar       |
| Key derivation           | `hashlib.sha256`                | `SHA256()`                 |

Both implementations use identical wire framing and DH parameters —
a C sender can transfer to a Python receiver and vice versa.

---

## Project Structure

```
secure-p2p/
├── python/
│   ├── peer.py          # CLI entry point — send & receive modes
│   ├── crypto_utils.py  # DH key exchange + AES-256-CBC
│   ├── transfer.py      # Chunked transfer + tqdm progress bar
│   └── integrity.py     # SHA-256 hash generation & verification
├── c/
│   ├── peer.c           # CLI entry point + POSIX socket helpers
│   ├── crypto_utils.c   # DH (OpenSSL BN) + AES (OpenSSL EVP)
│   ├── transfer.c       # Chunked transfer + progress bar
│   ├── integrity.c      # SHA-256 via OpenSSL EVP
│   ├── peer.h
│   ├── crypto_utils.h
│   ├── transfer.h
│   ├── integrity.h
│   └── Makefile
├── requirements.txt
└── README.md
```

---

## Quick Start

### Python

```bash
# Install dependencies
pip install -r requirements.txt

# Start receiver
python3 python/peer.py receive

# Send a file (in a second terminal)
python3 python/peer.py send <filepath> <receiver-ip>
```

### C

```bash
# macOS — install OpenSSL
brew install openssl@3

# Build
cd c && make

# Start receiver
./peer_c receive

# Send a file
./peer_c send <filepath> <receiver-ip>
```

### Custom Port

```bash
python3 python/peer.py receive --port 8888
python3 python/peer.py send file.zip 192.168.1.5 --port 8888
```

---

## Security Considerations

### What This Project Does Well
- **Forward secrecy per session** — a fresh DH private key is generated for
  every connection. Compromising one session key does not expose past or future
  sessions.
- **No key reuse** — a fresh random IV is generated for every encrypted chunk,
  so identical plaintext blocks always produce different ciphertext.
- **Subgroup validation** — received DH public keys are validated to be in the
  correct prime-order subgroup, preventing small-subgroup confinement attacks.
- **Constant-time comparison** — SHA-256 digests are compared using
  `hmac.compare_digest` (Python) and a manual XOR loop (C) to prevent
  timing side-channel attacks.
- **2048-bit safe prime** — uses RFC 3526 Group 14, which has been publicly
  audited and is widely considered secure against known attacks.

### Known Limitations (Production Gaps)
- **No authentication** — DH without authentication is vulnerable to a
  man-in-the-middle attack. A production system would use certificates
  (like TLS) or pre-shared keys to authenticate peers before the handshake.
- **Plain SHA-256 integrity, not HMAC** — an attacker who controls the
  network could replace both the file and its hash. A production system
  would use HMAC-SHA256 keyed with the session AES key so the integrity
  tag cannot be forged without knowing the key.
- **No replay protection** — a recorded session could theoretically be
  replayed. Production systems add a nonce or timestamp to the handshake.
- **AES-CBC vs AES-GCM** — AES-GCM provides authenticated encryption
  (confidentiality + integrity in one primitive). AES-CBC requires a
  separate integrity mechanism, which this project implements manually
  via SHA-256.

These gaps are intentional — this project prioritises implementing each
cryptographic primitive explicitly and transparently for educational clarity.

---

## Performance

Tested on Apple M-series (loopback interface):

| Transfer | Speed |
|----------|-------|
| Python → Python (10 MB) | ~170 MB/s |
| C → C (5 MB)            | ~287 MB/s |
| C → Python (5 MB)       | ~85 MB/s  |

---

## Dependencies

### Python
```
pycryptodome>=3.20.0
tqdm>=4.66.0
```

### C
- OpenSSL 3.x (`brew install openssl@3` on macOS)
- GCC or Clang with C99 support

---

## License

MIT — see [LICENSE](LICENSE)