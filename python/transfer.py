#!/usr/bin/env python3
"""
transfer.py — File transfer engine for secure-p2p

Stage 4: tqdm progress bar with speed and ETA
Stage 5: SHA-256 integrity verification

Handles:
  - Chunked sending with AES-256-CBC encryption
  - Chunked receiving with AES-256-CBC decryption
  - tqdm progress bar showing speed (MB/s) and ETA
  - SHA-256 hash sent after transfer, verified on receiver side
  - Returns transfer statistics (duration, average speed)
"""

import os
import struct
import time
from tqdm import tqdm

from crypto_utils import aes_encrypt, aes_decrypt
from integrity import hash_file, verify, format_hash


# ─── Constants ────────────────────────────────────────────────────────────────

CHUNK_SIZE    = 65536   # 64 KB per chunk
HEADER_FORMAT = ">Q"    # Big-endian unsigned 64-bit integer


# ─── Transfer statistics ──────────────────────────────────────────────────────

class TransferStats:
    """Holds the result of a completed transfer."""

    def __init__(self, filename: str, filesize: int, duration: float):
        self.filename  = filename
        self.filesize  = filesize
        self.duration  = duration
        self.avg_speed = filesize / duration if duration > 0 else 0

    def __str__(self) -> str:
        speed_mb = self.avg_speed / (1024 * 1024)
        size_mb  = self.filesize  / (1024 * 1024)
        return (
            f"\n{'─' * 50}\n"
            f"  File     : {self.filename}\n"
            f"  Size     : {size_mb:.2f} MB ({self.filesize:,} bytes)\n"
            f"  Duration : {self.duration:.2f}s\n"
            f"  Speed    : {speed_mb:.2f} MB/s (average)\n"
            f"{'─' * 50}"
        )


# ─── Send with progress bar + integrity hash ──────────────────────────────────

def send_file(sock, filepath: str, aes_key: bytes) -> TransferStats:
    """
    Send a file encrypted chunk by chunk with a progress bar.
    After the transfer, send the SHA-256 hash of the original file
    so the receiver can verify integrity.

    Protocol (in order):
        1. Encrypted filename
        2. Plaintext file size (8 bytes)
        3. N encrypted chunks
        4. SHA-256 hash of the original file (32 bytes, plaintext)
           — sent after all chunks so receiver can compare immediately
    """
    from peer import send_bytes

    filename = os.path.basename(filepath)
    filesize = os.path.getsize(filepath)

    # ── Compute hash of the original file BEFORE sending ──────────────────────
    # We hash first so we can report it alongside the transfer stats
    print(f"\n[*] Computing SHA-256 of '{filename}'...")
    file_hash = hash_file(filepath)
    print(f"[*] SHA-256: {format_hash(file_hash)}")

    # ── Send metadata ──────────────────────────────────────────────────────────
    send_bytes(sock, aes_encrypt(filename.encode("utf-8"), aes_key))
    send_bytes(sock, struct.pack(HEADER_FORMAT, filesize))

    print(f"\n[*] Sending '{filename}' ({filesize / (1024*1024):.2f} MB) — encrypted\n")

    # ── Progress bar ───────────────────────────────────────────────────────────
    bar = tqdm(
        total=filesize,
        unit="B",
        unit_scale=True,
        unit_divisor=1024,
        dynamic_ncols=True,
        colour="green",
        desc="  Sending",
        bar_format="{desc}: {percentage:3.0f}%|{bar}| {n_fmt}/{total_fmt} "
                   "[{elapsed}<{remaining}, {rate_fmt}]"
    )

    # ── Chunked encrypted send ─────────────────────────────────────────────────
    bytes_sent = 0
    start_time = time.monotonic()

    with open(filepath, "rb") as f:
        while True:
            chunk = f.read(CHUNK_SIZE)
            if not chunk:
                break
            send_bytes(sock, aes_encrypt(chunk, aes_key))
            bytes_sent += len(chunk)
            bar.update(len(chunk))

    bar.close()
    duration = time.monotonic() - start_time

    # ── Send integrity hash ────────────────────────────────────────────────────
    # Sent plaintext — 32 bytes, no length prefix needed (fixed size)
    # In production this would be HMAC-SHA256 keyed with aes_key
    sock.sendall(file_hash)
    print(f"\n[*] Integrity hash sent")

    stats = TransferStats(filename, filesize, duration)
    print(f"[+] Transfer complete{stats}")
    return stats


# ─── Receive with progress bar + integrity verification ───────────────────────

def receive_file(sock, aes_key: bytes, save_dir: str = ".") -> tuple[str, TransferStats]:
    """
    Receive and decrypt a file, then verify its SHA-256 integrity hash.

    After receiving all chunks, reads the 32-byte hash from the sender
    and compares it against SHA-256 of the saved file. Deletes the file
    and raises an error if verification fails.
    """
    from peer import recv_bytes, _recv_exact

    # ── Receive metadata ───────────────────────────────────────────────────────
    filename = aes_decrypt(recv_bytes(sock), aes_key).decode("utf-8")
    (filesize,) = struct.unpack(HEADER_FORMAT, recv_bytes(sock))

    save_path = os.path.join(save_dir, f"received_{filename}")

    print(f"\n[*] Receiving '{filename}' ({filesize / (1024*1024):.2f} MB) — decrypting\n")

    # ── Progress bar ───────────────────────────────────────────────────────────
    bar = tqdm(
        total=filesize,
        unit="B",
        unit_scale=True,
        unit_divisor=1024,
        dynamic_ncols=True,
        colour="cyan",
        desc="Receiving",
        bar_format="{desc}: {percentage:3.0f}%|{bar}| {n_fmt}/{total_fmt} "
                   "[{elapsed}<{remaining}, {rate_fmt}]"
    )

    # ── Chunked encrypted receive ──────────────────────────────────────────────
    bytes_received = 0
    start_time     = time.monotonic()

    with open(save_path, "wb") as f:
        while bytes_received < filesize:
            encrypted_chunk = recv_bytes(sock)
            chunk           = aes_decrypt(encrypted_chunk, aes_key)
            f.write(chunk)
            bytes_received += len(chunk)
            bar.update(len(chunk))

    bar.close()
    duration = time.monotonic() - start_time

    # ── Receive and verify integrity hash ─────────────────────────────────────
    # Read exactly 32 bytes — fixed size, no length prefix
    expected_hash = _recv_exact(sock, 32)
    print(f"\n[*] Verifying SHA-256 integrity...")
    print(f"[*] Expected : {format_hash(expected_hash)}")

    actual_hash = hash_file(save_path)
    print(f"[*] Actual   : {format_hash(actual_hash)}")

    # verify() raises ValueError and deletes save_path if hashes differ
    verify(expected_hash, actual_hash, filepath=save_path)
    print(f"[+] ✅ Integrity verified — file is authentic and complete")

    stats = TransferStats(filename, filesize, duration)
    print(f"[+] Transfer complete{stats}")
    return save_path, stats