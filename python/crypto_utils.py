#!/usr/bin/env python3
"""
crypto_utils.py — Cryptographic primitives for secure-p2p

Stage 2: Diffie-Hellman key exchange implemented from scratch.
Every mathematical operation is commented so you can explain it in an interview.

Stage 3 will add: AES-256-CBC encryption / decryption using the derived key.
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
#    The choice of g=2 with this specific p is proven to produce a group
#    of prime order, meaning no small-subgroup attacks are possible.

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
    16  # Parse as hexadecimal
)

DH_GENERATOR_G = 2


# ─── Diffie-Hellman Key Exchange ──────────────────────────────────────────────

class DiffieHellman:
    """
    Manual implementation of Diffie-Hellman key exchange over a 2048-bit
    safe prime group (RFC 3526, Group 14).

    Usage:
        dh = DiffieHellman()
        my_public_key  = dh.get_public_key()   # Send this to the other peer
        shared_secret  = dh.compute_shared_secret(their_public_key)
        aes_key        = dh.derive_aes_key(shared_secret)
    """

    def __init__(self):
        # Generate a cryptographically random private key.
        #
        # os.urandom(256) gives us 256 bytes = 2048 bits of OS-level randomness.
        # int.from_bytes() converts those bytes to a large integer.
        # The private key must stay secret — it never leaves this machine.
        self._private_key: int = int.from_bytes(os.urandom(256), byteorder="big")

        # Clamp the private key to be in range [2, p-2].
        # This is a safety measure — the extreme values 0, 1, p-1 produce
        # degenerate public keys that leak information.
        self._private_key = (self._private_key % (DH_PRIME_P - 2)) + 2

    def get_public_key(self) -> int:
        """
        Compute and return our public key.

        Formula: public_key = g^private_key mod p

        Python's built-in pow(g, private_key, p) uses fast modular
        exponentiation (square-and-multiply). This is O(log n) multiplications
        instead of O(n) — essential because private_key is ~2048 bits.

        The public key is SAFE TO SEND over the network in plaintext.
        An eavesdropper seeing g, p, and g^a mod p still cannot determine 'a'
        without solving the discrete logarithm problem.
        """
        return pow(DH_GENERATOR_G, self._private_key, DH_PRIME_P)

    def compute_shared_secret(self, their_public_key: int) -> int:
        """
        Compute the shared secret using the other peer's public key.

        Formula: shared_secret = their_public_key^our_private_key mod p
                               = (g^their_private)^our_private mod p
                               = g^(their_private * our_private) mod p

        The other peer computes:
                               = (g^our_private)^their_private mod p
                               = g^(our_private * their_private) mod p

        These are equal because multiplication is commutative.
        This equality is the entire foundation of Diffie-Hellman.

        We validate their public key first — accepting a malicious key
        (like 1 or p-1) could allow an attacker to force the shared
        secret to a predictable value.
        """
        self._validate_public_key(their_public_key)
        return pow(their_public_key, self._private_key, DH_PRIME_P)

    def derive_aes_key(self, shared_secret: int) -> bytes:
        """
        Derive a 256-bit AES key from the raw DH shared secret.

        Why not use the shared secret directly as the AES key?
        Two reasons:
          1. The shared secret is a 2048-bit integer — AES needs exactly 256 bits.
          2. The shared secret has mathematical structure (it's a group element).
             Hashing it with SHA-256 produces a uniformly random-looking 256-bit
             value with no exploitable structure.

        This operation is called a Key Derivation Function (KDF).
        A production system would use HKDF (RFC 5869) with a salt and info
        string for domain separation — SHA-256 is sufficient for our purposes.

        Returns:
            32 bytes (256 bits) suitable for use as an AES-256 key.
        """
        # Convert the shared secret integer to bytes (big-endian, 256 bytes)
        secret_bytes = shared_secret.to_bytes(256, byteorder="big")

        # SHA-256 hash produces exactly 32 bytes = 256 bits = AES-256 key size
        aes_key = hashlib.sha256(secret_bytes).digest()
        return aes_key

    @staticmethod
    def _validate_public_key(public_key: int) -> None:
        """
        Validate a received public key before using it.

        A malicious peer could send a crafted public key to force the
        shared secret to a known value. We check:
          - Key is in range [2, p-2] (excludes degenerate values 0, 1, p-1)
          - Key satisfies Fermat's little theorem for our prime (key^((p-1)/2) mod p == 1)
            This confirms the key is in the correct subgroup.
        """
        if not (2 <= public_key <= DH_PRIME_P - 2):
            raise ValueError(
                f"Received public key is out of valid range [2, p-2]. "
                f"Possible attack or implementation error."
            )

        # Subgroup check: for a safe prime p, (p-1)/2 is also prime.
        # A valid key must satisfy key^((p-1)/2) ≡ 1 (mod p).
        # This ensures the key is in the large prime-order subgroup,
        # preventing small subgroup confinement attacks.
        order = (DH_PRIME_P - 1) // 2
        if pow(public_key, order, DH_PRIME_P) != 1:
            raise ValueError(
                "Received public key failed subgroup validation. "
                "Key is not in the expected prime-order subgroup."
            )


# ─── Key serialisation helpers ────────────────────────────────────────────────
#
# Public keys are 2048-bit integers. We need to send them over the socket
# as bytes. We use a fixed 256-byte big-endian encoding — always the same
# size regardless of the key's value, which prevents length-based leakage.

def int_to_bytes(n: int) -> bytes:
    """Serialise a DH public key (up to 2048-bit) to 256 bytes, big-endian."""
    return n.to_bytes(256, byteorder="big")


def bytes_to_int(b: bytes) -> int:
    """Deserialise a 256-byte big-endian encoding back to an integer."""
    return int.from_bytes(b, byteorder="big")


# ─── Handshake orchestration ──────────────────────────────────────────────────

def perform_handshake_sender(sock) -> bytes:
    """
    Sender side of the DH handshake.

    Message flow:
        Sender  -->  public_key_A  -->  Receiver
        Sender  <--  public_key_B  <--  Receiver
        (both compute shared secret independently)
        (both derive identical AES key)

    Returns:
        32-byte AES key derived from the shared secret.
    """
    from peer import send_bytes, recv_bytes  # Import here to avoid circular import

    dh = DiffieHellman()

    # Step 1: Send our public key to the receiver
    our_public_key = dh.get_public_key()
    print("[*] DH: Sending public key to receiver...")
    send_bytes(sock, int_to_bytes(our_public_key))

    # Step 2: Receive the receiver's public key
    their_public_key_bytes = recv_bytes(sock)
    their_public_key = bytes_to_int(their_public_key_bytes)
    print("[*] DH: Received receiver's public key")

    # Step 3: Compute shared secret — this value is NEVER sent over the network
    shared_secret = dh.compute_shared_secret(their_public_key)
    print("[*] DH: Shared secret computed")

    # Step 4: Derive AES key from shared secret
    aes_key = dh.derive_aes_key(shared_secret)
    print(f"[+] DH: AES key derived — {aes_key.hex()[:16]}... (first 8 bytes shown)")

    return aes_key


def perform_handshake_receiver(sock) -> bytes:
    """
    Receiver side of the DH handshake.

    Mirror image of perform_handshake_sender — receives first, then sends.

    Returns:
        32-byte AES key derived from the shared secret.
        This will be identical to the key derived by the sender.
    """
    from peer import send_bytes, recv_bytes  # Import here to avoid circular import

    dh = DiffieHellman()

    # Step 1: Receive the sender's public key
    their_public_key_bytes = recv_bytes(sock)
    their_public_key = bytes_to_int(their_public_key_bytes)
    print("[*] DH: Received sender's public key")

    # Step 2: Send our public key to the sender
    our_public_key = dh.get_public_key()
    print("[*] DH: Sending public key to sender...")
    send_bytes(sock, int_to_bytes(our_public_key))

    # Step 3: Compute shared secret
    shared_secret = dh.compute_shared_secret(their_public_key)
    print("[*] DH: Shared secret computed")

    # Step 4: Derive AES key
    aes_key = dh.derive_aes_key(shared_secret)
    print(f"[+] DH: AES key derived — {aes_key.hex()[:16]}... (first 8 bytes shown)")

    return aes_key