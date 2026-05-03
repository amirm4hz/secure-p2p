#!/usr/bin/env python3
"""
transfer.py — File transfer engine for secure-p2p

Handles:
  - Chunked sending with AES-256-CBC encryption
  - Chunked receiving with AES-256-CBC decryption
  - tqdm progress bar showing speed (MB/s) and ETA
  - Returns transfer statistics (duration, average speed)

Used by peer.py — replaces the inline send_file / receive_file functions.
"""

import os
import struct
import time
from tqdm import tqdm

from crypto_utils import aes_encrypt, aes_decrypt


# ─── Constants ────────────────────────────────────────────────────────────────

CHUNK_SIZE    = 65536   # 64 KB — good balance of memory pressure vs syscall overhead
HEADER_FORMAT = ">Q"    # Big-endian unsigned 64-bit integer for length prefixing


# ─── Transfer statistics ──────────────────────────────────────────────────────

class TransferStats:
    """
    Holds the result of a completed transfer.
    Printed at the end of send and receive operations.
    """
    def __init__(self, filename: str, filesize: int, duration: float):
        self.filename  = filename
        self.filesize  = filesize
        self.duration  = duration                          # seconds
        self.avg_speed = filesize / duration if duration > 0 else 0  # bytes/sec

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


# ─── Send with progress bar ───────────────────────────────────────────────────

def send_file(sock, filepath: str, aes_key: bytes) -> TransferStats:
    """
    Send a file over an established socket, encrypted chunk by chunk,
    with a live tqdm progress bar showing bytes transferred, speed, and ETA.

    Protocol (in order):
        1. Encrypted filename
        2. Plaintext file size (8 bytes, big-endian) — needed for receiver's progress bar
        3. N encrypted chunks of CHUNK_SIZE bytes each

    Args:
        sock:     connected socket (from peer.py)
        filepath: path to the file to send
        aes_key:  32-byte AES-256 key from DH handshake

    Returns:
        TransferStats object with size, duration, average speed
    """
    from peer import send_bytes  # avoid circular import at module level

    filename = os.path.basename(filepath)
    filesize = os.path.getsize(filepath)

    # ── Send metadata ──────────────────────────────────────────────────────────
    # Filename is encrypted — even the filename is private
    send_bytes(sock, aes_encrypt(filename.encode("utf-8"), aes_key))
    # File size sent plaintext so receiver can initialise its progress bar
    send_bytes(sock, struct.pack(HEADER_FORMAT, filesize))

    print(f"\n[*] Sending '{filename}' ({filesize / (1024*1024):.2f} MB) — encrypted\n")

    # ── Progress bar setup ────────────────────────────────────────────────────
    # unit='B'        → label bytes as 'B'
    # unit_scale=True → auto-convert to KB/MB/GB
    # unit_divisor=1024 → use 1024-based units (KiB, MiB) not 1000-based
    # dynamic_ncols=True → resize bar if terminal width changes
    # colour='green'  → green bar on supported terminals
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

    # ── Chunked encrypted send ────────────────────────────────────────────────
    bytes_sent = 0
    start_time = time.monotonic()  # monotonic clock — unaffected by system time changes

    with open(filepath, "rb") as f:
        while True:
            chunk = f.read(CHUNK_SIZE)
            if not chunk:
                break  # EOF

            # Encrypt this chunk — each chunk gets its own random IV
            encrypted_chunk = aes_encrypt(chunk, aes_key)
            send_bytes(sock, encrypted_chunk)

            bytes_sent += len(chunk)
            bar.update(len(chunk))   # advance progress bar by plaintext bytes

    bar.close()
    duration = time.monotonic() - start_time

    stats = TransferStats(filename, filesize, duration)
    print(f"\n[+] Transfer complete{stats}")
    return stats


# ─── Receive with progress bar ────────────────────────────────────────────────

def receive_file(sock, aes_key: bytes, save_dir: str = ".") -> tuple[str, TransferStats]:
    """
    Receive and decrypt a file from an established socket connection,
    with a live tqdm progress bar.

    Args:
        sock:     connected socket (from peer.py)
        aes_key:  32-byte AES-256 key from DH handshake
        save_dir: directory to save the received file into

    Returns:
        Tuple of (save_path, TransferStats)
    """
    from peer import recv_bytes  # avoid circular import at module level

    # ── Receive metadata ───────────────────────────────────────────────────────
    filename = aes_decrypt(recv_bytes(sock), aes_key).decode("utf-8")
    (filesize,) = struct.unpack(HEADER_FORMAT, recv_bytes(sock))

    save_path = os.path.join(save_dir, f"received_{filename}")

    print(f"\n[*] Receiving '{filename}' ({filesize / (1024*1024):.2f} MB) — decrypting\n")

    # ── Progress bar setup ────────────────────────────────────────────────────
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

    # ── Chunked encrypted receive ─────────────────────────────────────────────
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

    stats = TransferStats(filename, filesize, duration)
    print(f"\n[+] Transfer complete{stats}")
    return save_path, stats