#!/usr/bin/env python3
"""
crypto_utils.py — Cryptographic primitives for secure-p2p

Stage 2: Diffie-Hellman key exchange implemented from scratch.
Stage 3: AES-256-CBC encryption and decryption.

Every mathematical operation is commented so you can explain it in an interview.
"""

import os
import hashlib
import struct


# ─── Diffie-Hellman Parameters (RFC 3526, Group 14 — 2048-bit MODP) ──────────
#
# These two numbers are PUBLIC — hardcoded and identical on both sides.
# Using a standardised prime from RFC 3526 is intentional: it has been
# audited by the cryptography community and is known to be safe.
#
# p: a 2048-bit safe prime. "Safe" means (p-1)/2 is also prime, which
#    prevents certain subgroup attacks against DH.
#
# g: the generator, 2. Every possible shared secret is a power of g mod p.

DH_PRIME_P = int(
    "FFFFFFFF FFFFFFFF C90FDAA2 2168C234 C4C6628B 80DC1CD1"
    "29024E08 8A67CC74 020BBEA6 3B139B22 514A0879 8E3404DD"
    "EF9519B3 CD3A431B 302B0A6D F25F1437 4FE1356D 6D51C245"
    "E485B576 625E7EC6 F44C42E9 A637ED6B 0BFF5CB6 F406B7ED"
    "EE386BFB 5A899FA5 AE9F2411 7C4B1FE6 49286651 ECE45B3D"
    "C2007CB8 A163BF05 98DA4836 1C55D39A 69163FA8 FD24CF5F"
    "83655D23 DCA3AD96 1C62F356 208552BB 9ED52907 7096966D"
    "670C354E 4ABC9804 F1746C08 CA18217C 32905E46 2E36CE3B"
    "E39E772C 180E8603 9B2783A2 EC07A28F B5C55DF0 6F4C52C9"
    "DE2BCBF6 95581718 3995497C EA956AE5 15D22618 98FA0510"
    "15728E5A 8AACAA68 FFFFFFFF FFFFFFFF".replace(" ", ""),
    16
)

DH_GENERATOR_G = 2

# AES block size is always 16 bytes — this is fixed by the AES standard
AES_BLOCK_SIZE = 16


# ─── Diffie-Hellman Key Exchange ──────────────────────────────────────────────

class DiffieHellman:
    """
    Manual implementation of Diffie-Hellman key exchange over a 2048-bit
    safe prime group (RFC 3526, Group 14).
    """

    def __init__(self):
        # Generate a cryptographically random private key.
        # os.urandom(256) gives 256 bytes = 2048 bits of OS-level randomness.
        self._private_key: int = int.from_bytes(os.urandom(256), byteorder="big")
        # Clamp to [2, p-2] to avoid degenerate values
        self._private_key = (self._private_key % (DH_PRIME_P - 2)) + 2

    def get_public_key(self) -> int:
        """
        Compute our public key: g^private_key mod p
        Python's pow(g, e, m) uses fast modular exponentiation — O(log n).
        """
        return pow(DH_GENERATOR_G, self._private_key, DH_PRIME_P)

    def compute_shared_secret(self, their_public_key: int) -> int:
        """
        Compute shared secret: their_public_key^our_private_key mod p
        Both sides arrive at g^(a*b) mod p independently.
        """
        self._validate_public_key(their_public_key)
        return pow(their_public_key, self._private_key, DH_PRIME_P)

    def derive_aes_key(self, shared_secret: int) -> bytes:
        """
        Derive a 256-bit AES key from the raw DH shared secret via SHA-256.
        SHA-256 removes mathematical structure and produces uniform 32 bytes.
        """
        secret_bytes = shared_secret.to_bytes(256, byteorder="big")
        return hashlib.sha256(secret_bytes).digest()

    @staticmethod
    def _validate_public_key(public_key: int) -> None:
        """
        Validate received public key is in range [2, p-2] and in the
        correct subgroup. Prevents small-subgroup confinement attacks.
        """
        if not (2 <= public_key <= DH_PRIME_P - 2):
            raise ValueError("Received public key is out of valid range [2, p-2].")
        order = (DH_PRIME_P - 1) // 2
        if pow(public_key, order, DH_PRIME_P) != 1:
            raise ValueError("Received public key failed subgroup validation.")


# ─── Key serialisation helpers ────────────────────────────────────────────────

def int_to_bytes(n: int) -> bytes:
    """Serialise a DH public key (up to 2048-bit) to 256 bytes, big-endian."""
    return n.to_bytes(256, byteorder="big")


def bytes_to_int(b: bytes) -> int:
    """Deserialise a 256-byte big-endian encoding back to an integer."""
    return int.from_bytes(b, byteorder="big")


# ─── PKCS#7 Padding ───────────────────────────────────────────────────────────

def pkcs7_pad(data: bytes) -> bytes:
    """
    Apply PKCS#7 padding to make data a multiple of AES_BLOCK_SIZE (16 bytes).

    How it works:
      - Calculate how many bytes are needed to reach the next 16-byte boundary
      - Append that many bytes, each with the numeric value of the pad length
      - If data is already a multiple of 16, append a full 16-byte padding block
        (so the receiver can always unambiguously strip padding)

    Example:
      data = b"HELLO" (5 bytes)
      pad_len = 16 - (5 % 16) = 11
      padded  = b"HELLO" + bytes([11] * 11)
    """
    pad_len = AES_BLOCK_SIZE - (len(data) % AES_BLOCK_SIZE)
    return data + bytes([pad_len] * pad_len)


def pkcs7_unpad(data: bytes) -> bytes:
    """
    Remove PKCS#7 padding after decryption.

    The last byte tells us how many padding bytes were appended.
    We validate all padding bytes have the correct value before stripping —
    a padding oracle attack exploits implementations that don't validate this.

    Raises ValueError if padding is malformed (possible tampering).
    """
    if not data:
        raise ValueError("Cannot unpad empty data")

    pad_len = data[-1]  # Last byte = padding length

    # Sanity check: padding length must be 1–16
    if pad_len < 1 or pad_len > AES_BLOCK_SIZE:
        raise ValueError(f"Invalid PKCS#7 padding length: {pad_len}")

    # Verify every padding byte has the correct value
    padding = data[-pad_len:]
    if padding != bytes([pad_len] * pad_len):
        raise ValueError("Invalid PKCS#7 padding — data may have been tampered with")

    return data[:-pad_len]


# ─── AES-256-CBC Encryption / Decryption ─────────────────────────────────────
#
# We use pycryptodome (imported as Crypto) for the raw AES block operations.
# The CBC chaining logic is handled by pycryptodome's CBC mode.
# The IV generation, padding, and framing are our responsibility.

def aes_encrypt(plaintext: bytes, key: bytes) -> bytes:
    """
    Encrypt plaintext using AES-256-CBC.

    Steps:
      1. Generate a random 16-byte IV (never reuse an IV with the same key)
      2. Pad plaintext to a multiple of 16 bytes using PKCS#7
      3. Encrypt with AES-256-CBC using key + IV
      4. Prepend IV to ciphertext (receiver needs it to decrypt)

    Wire format: [16-byte IV][ciphertext]

    Args:
        plaintext: raw bytes to encrypt (any length)
        key:       32-byte AES-256 key (from DH key derivation)

    Returns:
        IV + ciphertext as a single bytes object
    """
    from Crypto.Cipher import AES  # pycryptodome

    if len(key) != 32:
        raise ValueError(f"AES-256 requires a 32-byte key, got {len(key)} bytes")

    # Step 1: Fresh random IV for every encryption — critical for CBC security.
    # Reusing an IV with the same key leaks XOR of the first plaintext blocks.
    iv = os.urandom(AES_BLOCK_SIZE)

    # Step 2: Pad to block boundary
    padded = pkcs7_pad(plaintext)

    # Step 3: Encrypt — pycryptodome handles the CBC XOR chaining internally
    cipher = AES.new(key, AES.MODE_CBC, iv)
    ciphertext = cipher.encrypt(padded)

    # Step 4: Prepend IV so receiver can decrypt
    return iv + ciphertext


def aes_decrypt(ciphertext_with_iv: bytes, key: bytes) -> bytes:
    """
    Decrypt AES-256-CBC ciphertext produced by aes_encrypt().

    Steps:
      1. Split off the first 16 bytes as the IV
      2. Decrypt the remainder with AES-256-CBC using key + IV
      3. Strip PKCS#7 padding to recover original plaintext

    Args:
        ciphertext_with_iv: IV + ciphertext (as returned by aes_encrypt)
        key:                32-byte AES-256 key (must match encryption key)

    Returns:
        Original plaintext bytes
    """
    from Crypto.Cipher import AES  # pycryptodome

    if len(key) != 32:
        raise ValueError(f"AES-256 requires a 32-byte key, got {len(key)} bytes")

    if len(ciphertext_with_iv) < AES_BLOCK_SIZE:
        raise ValueError("Ciphertext too short to contain IV")

    # Step 1: Extract IV from the first 16 bytes
    iv         = ciphertext_with_iv[:AES_BLOCK_SIZE]
    ciphertext = ciphertext_with_iv[AES_BLOCK_SIZE:]

    # Step 2: Decrypt
    cipher    = AES.new(key, AES.MODE_CBC, iv)
    padded    = cipher.decrypt(ciphertext)

    # Step 3: Strip padding
    plaintext = pkcs7_unpad(padded)

    return plaintext


# ─── Handshake orchestration ──────────────────────────────────────────────────

def perform_handshake_sender(sock) -> bytes:
    """
    Sender side of the DH handshake.
    Returns 32-byte AES key derived from the shared secret.
    """
    from peer import send_bytes, recv_bytes

    dh = DiffieHellman()

    our_public_key = dh.get_public_key()
    print("[*] DH: Sending public key to receiver...")
    send_bytes(sock, int_to_bytes(our_public_key))

    their_public_key_bytes = recv_bytes(sock)
    their_public_key = bytes_to_int(their_public_key_bytes)
    print("[*] DH: Received receiver's public key")

    shared_secret = dh.compute_shared_secret(their_public_key)
    print("[*] DH: Shared secret computed")

    aes_key = dh.derive_aes_key(shared_secret)
    print(f"[+] DH: AES-256 key derived — {aes_key.hex()[:16]}... (first 8 bytes shown)")

    return aes_key


def perform_handshake_receiver(sock) -> bytes:
    """
    Receiver side of the DH handshake.
    Returns 32-byte AES key — identical to the sender's derived key.
    """
    from peer import send_bytes, recv_bytes

    dh = DiffieHellman()

    their_public_key_bytes = recv_bytes(sock)
    their_public_key = bytes_to_int(their_public_key_bytes)
    print("[*] DH: Received sender's public key")

    our_public_key = dh.get_public_key()
    print("[*] DH: Sending public key to sender...")
    send_bytes(sock, int_to_bytes(our_public_key))

    shared_secret = dh.compute_shared_secret(their_public_key)
    print("[*] DH: Shared secret computed")

    aes_key = dh.derive_aes_key(shared_secret)
    print(f"[+] DH: AES-256 key derived — {aes_key.hex()[:16]}... (first 8 bytes shown)")

    return aes_key