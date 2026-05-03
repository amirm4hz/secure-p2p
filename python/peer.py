#!/usr/bin/env python3
"""
secure-p2p — Encrypted P2P File Sharing CLI Tool
Stage 3: AES-256-CBC encryption wired into file transfer

Usage:
    Receive mode: python3 peer.py receive [--port PORT]
    Send mode:    python3 peer.py send <filepath> <host> [--port PORT]
"""

import socket
import struct
import os
import sys
import argparse
from crypto_utils import (
    perform_handshake_sender,
    perform_handshake_receiver,
    aes_encrypt,
    aes_decrypt,
)


# ─── Constants ────────────────────────────────────────────────────────────────

DEFAULT_PORT  = 9999
CHUNK_SIZE    = 65536   # 64 KB per chunk
HEADER_FORMAT = ">Q"    # Big-endian unsigned 64-bit integer (8 bytes)
HEADER_SIZE   = struct.calcsize(HEADER_FORMAT)


# ─── Low-level send / recv helpers ────────────────────────────────────────────

def send_bytes(sock: socket.socket, data: bytes) -> None:
    """Send length-prefixed bytes. Protocol: [8-byte length][data]"""
    header = struct.pack(HEADER_FORMAT, len(data))
    sock.sendall(header)
    sock.sendall(data)


def recv_bytes(sock: socket.socket) -> bytes:
    """Receive one complete length-prefixed message."""
    header = _recv_exact(sock, HEADER_SIZE)
    if not header:
        raise ConnectionError("Connection closed before header received")
    (length,) = struct.unpack(HEADER_FORMAT, header)
    data = _recv_exact(sock, length)
    if not data:
        raise ConnectionError("Connection closed before full message received")
    return data


def _recv_exact(sock: socket.socket, n: int) -> bytes:
    """Read exactly n bytes, looping until all arrive."""
    buf = bytearray()
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("Socket closed mid-stream")
        buf.extend(chunk)
    return bytes(buf)


# ─── File transfer (AES-256-CBC encrypted) ────────────────────────────────────

def send_file(sock: socket.socket, filepath: str, aes_key: bytes) -> None:
    """
    Send a file over an established socket connection, encrypted with AES-256-CBC.

    What gets encrypted:
      - The filename (so even the filename is private)
      - Every chunk of file data

    What stays plaintext:
      - The file size (receiver needs this to know when transfer is complete)
        In a production system you'd encrypt this too and use authenticated
        encryption (AES-GCM) — noted in README security considerations.
    """
    filename = os.path.basename(filepath)
    filesize = os.path.getsize(filepath)

    print(f"[*] Sending '{filename}' ({filesize:,} bytes) — AES-256-CBC encrypted")

    # Encrypt and send filename
    send_bytes(sock, aes_encrypt(filename.encode("utf-8"), aes_key))

    # Send file size plaintext (needed for progress tracking)
    send_bytes(sock, struct.pack(HEADER_FORMAT, filesize))

    # Encrypt and send file data chunk by chunk
    bytes_sent = 0
    with open(filepath, "rb") as f:
        while True:
            chunk = f.read(CHUNK_SIZE)
            if not chunk:
                break
            encrypted_chunk = aes_encrypt(chunk, aes_key)
            send_bytes(sock, encrypted_chunk)
            bytes_sent += len(chunk)
            print(f"\r[*] Progress: {bytes_sent:,} / {filesize:,} bytes", end="", flush=True)

    print(f"\n[+] File sent and encrypted successfully: {bytes_sent:,} bytes")


def receive_file(sock: socket.socket, aes_key: bytes, save_dir: str = ".") -> str:
    """
    Receive and decrypt a file from an established socket connection.
    """
    # Decrypt filename
    filename = aes_decrypt(recv_bytes(sock), aes_key).decode("utf-8")

    # Receive plaintext file size
    (filesize,) = struct.unpack(HEADER_FORMAT, recv_bytes(sock))

    print(f"[*] Receiving '{filename}' ({filesize:,} bytes) — decrypting AES-256-CBC")

    save_path      = os.path.join(save_dir, f"received_{filename}")
    bytes_received = 0

    with open(save_path, "wb") as f:
        while bytes_received < filesize:
            encrypted_chunk = recv_bytes(sock)
            chunk = aes_decrypt(encrypted_chunk, aes_key)
            f.write(chunk)
            bytes_received += len(chunk)
            print(f"\r[*] Progress: {bytes_received:,} / {filesize:,} bytes", end="", flush=True)

    print(f"\n[+] File received and decrypted: {save_path}")
    return save_path


# ─── Receive mode ─────────────────────────────────────────────────────────────

def run_receiver(port: int) -> None:
    server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_sock.bind(("0.0.0.0", port))
    server_sock.listen(1)

    print(f"[*] Listening on 0.0.0.0:{port} — waiting for sender...")

    try:
        conn, addr = server_sock.accept()
        print(f"[+] Connection established from {addr[0]}:{addr[1]}")

        with conn:
            aes_key = perform_handshake_receiver(conn)
            receive_file(conn, aes_key)

    except KeyboardInterrupt:
        print("\n[!] Receiver stopped by user")
    finally:
        server_sock.close()


# ─── Send mode ────────────────────────────────────────────────────────────────

def run_sender(filepath: str, host: str, port: int) -> None:
    if not os.path.exists(filepath):
        print(f"[!] Error: file not found: {filepath}")
        sys.exit(1)

    print(f"[*] Connecting to {host}:{port} ...")

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    try:
        sock.connect((host, port))
        print(f"[+] Connected to {host}:{port}")

        with sock:
            aes_key = perform_handshake_sender(sock)
            send_file(sock, filepath, aes_key)

    except ConnectionRefusedError:
        print(f"[!] Connection refused — is the receiver running on {host}:{port}?")
        sys.exit(1)
    except Exception as e:
        print(f"[!] Error: {e}")
        sys.exit(1)


# ─── CLI entry point ──────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="secure-p2p: Encrypted P2P file transfer",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  Start receiver:      python3 peer.py receive
  Start receiver:      python3 peer.py receive --port 8888
  Send a file:         python3 peer.py send photo.jpg 192.168.1.5
  Send a file:         python3 peer.py send photo.jpg 192.168.1.5 --port 8888
        """
    )

    subparsers = parser.add_subparsers(dest="mode", required=True)

    recv_parser = subparsers.add_parser("receive", help="Listen for incoming file transfer")
    recv_parser.add_argument("--port", type=int, default=DEFAULT_PORT,
                             help=f"Port to listen on (default: {DEFAULT_PORT})")

    send_parser = subparsers.add_parser("send", help="Send a file to a receiver")
    send_parser.add_argument("filepath", help="Path to the file to send")
    send_parser.add_argument("host",     help="Receiver's IP address or hostname")
    send_parser.add_argument("--port",   type=int, default=DEFAULT_PORT,
                             help=f"Receiver's port (default: {DEFAULT_PORT})")

    args = parser.parse_args()

    if args.mode == "receive":
        run_receiver(args.port)
    elif args.mode == "send":
        run_sender(args.filepath, args.host, args.port)


if __name__ == "__main__":
    main()