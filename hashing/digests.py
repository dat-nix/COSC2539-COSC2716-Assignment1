"""Reusable cryptographic digest functions for byte strings."""

import hashlib


def sha256(data: bytes) -> bytes:
    """Return the SHA-256 digest of *data* as 32 bytes."""
    return hashlib.sha256(data).digest()


def sha3_256(data: bytes) -> bytes:
    """Return the SHA3-256 digest of *data* as 32 bytes."""
    return hashlib.sha3_256(data).digest()


def blake2b_256(data: bytes) -> bytes:
    """Return a 32-byte BLAKE2b digest of *data*."""
    return hashlib.blake2b(data, digest_size=32).digest()
