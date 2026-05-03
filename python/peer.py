#!/usr/bin/env python3
"""
secure-p2p — Encrypted P2P File Sharing CLI Tool
Stage 1: TCP socket foundation (no encryption yet)

Usage:
    Receive mode: python3 peer.py receive [--port PORT]
    Send mode:    python3 peer.py send <filepath> <host> [--port PORT]
"""

import socket
import struct
import os
import sys
import argparse

# ─── Constants ────────────────────────────────────────────────────────────────

DEFAULT_PORT    = 9999
CHUNK_SIZE      = 65536   # 64 KB per chunk — good balance of memory vs syscall overhead
HEADER_FORMAT   = ">Q"    # Big-endian unsigned 64-bit integer (8 bytes)
HEADER_SIZE     = struct.calcsize(HEADER_FORMAT)  # Always 8


# ─── Low-level send / recv helpers ────────────────────────────────────────────

def send_bytes(sock: socket.socket, data: bytes) -> None:
    """
    Send an arbitrary blob of bytes over a socket, prefixed with its length.

    Protocol: [8-byte big-endian length][data bytes]

    Why length-prefix? TCP is a stream protocol — it has no concept of
    message boundaries. Without this, the receiver can't know if it has
    received a complete message or just part of one.
    """
    length = len(data)
    header = struct.pack(HEADER_FORMAT, length)  # Pack length into 8 bytes
    sock.sendall(header)                          # sendall() retries until all bytes sent
    sock.sendall(data)


def recv_bytes(sock: socket.socket) -> bytes:
    """
    Receive exactly one length-prefixed message from a socket.

    Reads the 8-byte header first to learn how many bytes to expect,
    then reads exactly that many bytes. Loops internally because TCP
    may deliver data in smaller chunks than requested (kernel buffering).
    """
    # Step 1: Read exactly 8 bytes for the length header
    header = _recv_exact(sock, HEADER_SIZE)
    if not header:
        raise ConnectionError("Connection closed before header received")

    # Step 2: Unpack the length from the header
    (length,) = struct.unpack(HEADER_FORMAT, header)

    # Step 3: Read exactly `length` bytes
    data = _recv_exact(sock, length)
    if not data:
        raise ConnectionError("Connection closed before full message received")

    return data


def _recv_exact(sock: socket.socket, n: int) -> bytes:
    """
    Read exactly n bytes from sock. Loops until all n bytes arrive.

    TCP may return fewer bytes than requested in a single recv() call —
    this is normal and expected. We loop until we have exactly what we need.
    """
    buf = bytearray()
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))  # Ask only for what's still missing
        if not chunk:
            raise ConnectionError("Socket closed mid-stream")
        buf.extend(chunk)
    return bytes(buf)


# ─── File transfer (plaintext — encryption added in Stage 3) ──────────────────

def send_file(sock: socket.socket, filepath: str) -> None:
    """
    Send a file over an established socket connection.

    Sends in this order:
        1. Filename (so receiver knows what to save it as)
        2. File size in bytes (so receiver can show progress)
        3. File contents in CHUNK_SIZE chunks
    """
    filename  = os.path.basename(filepath)
    filesize  = os.path.getsize(filepath)

    print(f"[*] Sending '{filename}' ({filesize:,} bytes)")

    # Send filename
    send_bytes(sock, filename.encode("utf-8"))

    # Send file size as an 8-byte big-endian integer
    send_bytes(sock, struct.pack(HEADER_FORMAT, filesize))

    # Send file contents chunk by chunk
    bytes_sent = 0
    with open(filepath, "rb") as f:
        while True:
            chunk = f.read(CHUNK_SIZE)
            if not chunk:
                break
            send_bytes(sock, chunk)
            bytes_sent += len(chunk)
            # Simple progress indicator — replaced with rich progress bar in Stage 4
            print(f"\r[*] Progress: {bytes_sent:,} / {filesize:,} bytes", end="", flush=True)

    print(f"\n[+] File sent successfully: {bytes_sent:,} bytes transmitted")


def receive_file(sock: socket.socket, save_dir: str = ".") -> str:
    """
    Receive a file from an established socket connection.

    Returns the path of the saved file.
    """
    # Receive filename
    filename = recv_bytes(sock).decode("utf-8")

    # Receive file size
    (filesize,) = struct.unpack(HEADER_FORMAT, recv_bytes(sock))

    print(f"[*] Receiving '{filename}' ({filesize:,} bytes)")

    # Save as received_<filename> to avoid overwriting local files
    save_path    = os.path.join(save_dir, f"received_{filename}")
    bytes_received = 0

    with open(save_path, "wb") as f:
        while bytes_received < filesize:
            chunk = recv_bytes(sock)
            f.write(chunk)
            bytes_received += len(chunk)
            print(f"\r[*] Progress: {bytes_received:,} / {filesize:,} bytes", end="", flush=True)

    print(f"\n[+] File received and saved to: {save_path}")
    return save_path


# ─── Receive mode ─────────────────────────────────────────────────────────────

def run_receiver(port: int) -> None:
    """
    Listen for an incoming connection, then receive a file.

    SO_REUSEADDR lets us restart the server immediately after stopping it
    without waiting for the OS to release the port (avoids 'Address already
    in use' errors during development).
    """
    server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_sock.bind(("0.0.0.0", port))  # Listen on all interfaces
    server_sock.listen(1)                # Queue up to 1 pending connection

    print(f"[*] Listening on 0.0.0.0:{port} — waiting for sender...")

    try:
        conn, addr = server_sock.accept()  # Blocks here until sender connects
        print(f"[+] Connection established from {addr[0]}:{addr[1]}")

        with conn:
            receive_file(conn)

    except KeyboardInterrupt:
        print("\n[!] Receiver stopped by user")
    finally:
        server_sock.close()


# ─── Send mode ────────────────────────────────────────────────────────────────

def run_sender(filepath: str, host: str, port: int) -> None:
    """
    Connect to a receiver and send a file.
    """
    if not os.path.exists(filepath):
        print(f"[!] Error: file not found: {filepath}")
        sys.exit(1)

    print(f"[*] Connecting to {host}:{port} ...")

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    try:
        sock.connect((host, port))
        print(f"[+] Connected to {host}:{port}")

        with sock:
            send_file(sock, filepath)

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

    # — receive subcommand —
    recv_parser = subparsers.add_parser("receive", help="Listen for incoming file transfer")
    recv_parser.add_argument("--port", type=int, default=DEFAULT_PORT,
                             help=f"Port to listen on (default: {DEFAULT_PORT})")

    # — send subcommand —
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