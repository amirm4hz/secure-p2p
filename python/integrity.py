#!/usr/bin/env python3
"""
integrity.py — SHA-256 file integrity verification for secure-p2p

Provides:
  - hash_file()   : compute SHA-256 of a file on disk
  - hash_bytes()  : compute SHA-256 of an in-memory bytes object
  - verify()      : compare two hashes and raise if they differ

SHA-256 produces a 32-byte (256-bit) digest. Any change to the input —
even a single flipped bit — produces a completely different digest.
This property (the avalanche effect) makes it suitable for integrity checks.

Interview note:
  We use plain SHA-256 here for clarity. A production implementation would
  use HMAC-SHA256 (keyed with the AES key) so the integrity tag cannot be
  forged by an attacker who controls the network connection. This is noted
  in the README security considerations section.
"""

import hashlib
import os


# SHA-256 digest is always exactly 32 bytes
SHA256_DIGEST_SIZE = 32

# Read files in 64KB chunks to avoid loading large files into memory
HASH_CHUNK_SIZE = 65536


def hash_file(filepath: str) -> bytes:
    """
    Compute the SHA-256 hash of a file on disk.

    Reads the file in HASH_CHUNK_SIZE chunks so arbitrarily large files
    can be hashed without loading them entirely into memory. SHA-256 is
    an incremental algorithm — you feed it data in pieces and call
    digest() at the end to get the final hash.

    Args:
        filepath: path to the file to hash

    Returns:
        32-byte SHA-256 digest

    Example:
        >>> hash_file("photo.jpg")
        b'\\x3a\\x7f...'  # 32 bytes
    """
    sha256 = hashlib.sha256()

    with open(filepath, "rb") as f:
        while True:
            chunk = f.read(HASH_CHUNK_SIZE)
            if not chunk:
                break
            sha256.update(chunk)  # Feed chunk into the running hash state

    return sha256.digest()  # Finalise and return 32-byte digest


def hash_bytes(data: bytes) -> bytes:
    """
    Compute the SHA-256 hash of an in-memory bytes object.

    Used in tests and for hashing small data (like filenames).

    Args:
        data: bytes to hash

    Returns:
        32-byte SHA-256 digest
    """
    return hashlib.sha256(data).digest()


def verify(expected_hash: bytes, actual_hash: bytes, filepath: str = "") -> None:
    """
    Compare two SHA-256 digests and raise an error if they differ.

    Uses a constant-time comparison (hmac.compare_digest) to prevent
    timing attacks — an attacker measuring how long comparison takes
    could otherwise deduce how many bytes match.

    Args:
        expected_hash: the hash sent by the sender (32 bytes)
        actual_hash:   the hash computed by the receiver (32 bytes)
        filepath:      optional — path to delete if verification fails

    Raises:
        ValueError: if hashes do not match (with hex digests for debugging)
    """
    import hmac  # stdlib — used only for constant-time comparison

    if len(expected_hash) != SHA256_DIGEST_SIZE or len(actual_hash) != SHA256_DIGEST_SIZE:
        raise ValueError(
            f"Hash length mismatch — expected {SHA256_DIGEST_SIZE} bytes, "
            f"got expected={len(expected_hash)}, actual={len(actual_hash)}"
        )

    # hmac.compare_digest() is constant-time — takes the same amount of time
    # regardless of how many bytes match. This prevents timing side-channels.
    if not hmac.compare_digest(expected_hash, actual_hash):
        # If a filepath was given, delete the corrupted file
        if filepath and os.path.exists(filepath):
            os.remove(filepath)
            print(f"[!] Deleted corrupted file: {filepath}")

        raise ValueError(
            f"Integrity check FAILED — file may be corrupted or tampered with\n"
            f"  Expected : {expected_hash.hex()}\n"
            f"  Actual   : {actual_hash.hex()}"
        )


def format_hash(digest: bytes) -> str:
    """
    Format a 32-byte digest as a human-readable hex string with spaces
    every 8 characters for readability.

    Example: 'a3f8bc12 e9d47210 3a7f9b21 c4e85d01 ...'
    """
    hex_str = digest.hex()
    return " ".join(hex_str[i:i+8] for i in range(0, len(hex_str), 8))