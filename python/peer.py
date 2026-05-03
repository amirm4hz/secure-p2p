#!/usr/bin/env python3
"""
secure-p2p — Encrypted P2P File Sharing CLI Tool
Stage 4: Progress bar with speed and ETA via tqdm

Usage:
    Receive mode: python3 peer.py receive [--port PORT]
    Send mode:    python3 peer.py send <filepath> <host> [--port PORT]
"""

import socket
import struct
import os
import sys
import argparse

from crypto_utils import perform_handshake_sender, perform_handshake_receiver
from transfer import send_file, receive_file


# ─── Constants ────────────────────────────────────────────────────────────────

DEFAULT_PORT  = 9999
HEADER_FORMAT = ">Q"
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
            receive_file(conn, aes_key)         # ← now from transfer.py

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
            send_file(sock, filepath, aes_key)  # ← now from transfer.py

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