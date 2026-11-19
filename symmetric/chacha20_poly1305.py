"""ChaCha20-Poly1305 authenticated encryption."""

from __future__ import annotations

import secrets

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

from symmetric.common import CiphertextEnvelope, InvalidCiphertextError, require_bytes


NAME = "ChaCha20-Poly1305"
KEY_BYTES = 32
NONCE_BYTES = 12
TAG_BYTES = 16
_AAD = b"COSC2539:ChaCha20-Poly1305:v1"


def generate_key() -> bytes:
    """Create a fresh 256-bit key using the operating system CSPRNG."""
    return ChaCha20Poly1305.generate_key()


def encrypt(plaintext: bytes, key: bytes) -> CiphertextEnvelope:
    """Encrypt bytes with a fresh 96-bit nonce and Poly1305 tag."""
    if not isinstance(plaintext, bytes):
        raise TypeError("plaintext must be bytes")
    if not isinstance(key, bytes) or len(key) != KEY_BYTES:
        raise ValueError("ChaCha20-Poly1305 key must contain exactly 32 bytes")
    nonce = secrets.token_bytes(NONCE_BYTES)
    ciphertext_and_tag = ChaCha20Poly1305(key).encrypt(nonce, plaintext, _AAD)
    return CiphertextEnvelope(
        scheme=NAME,
        nonce=nonce,
        ciphertext=ciphertext_and_tag[:-TAG_BYTES],
        tag=ciphertext_and_tag[-TAG_BYTES:],
    )


def decrypt(envelope: CiphertextEnvelope, key: bytes) -> bytes:
    """Authenticate and decrypt, returning no plaintext on any failure."""
    if not isinstance(key, bytes) or len(key) != KEY_BYTES:
        raise InvalidCiphertextError("key_validation")
    if not isinstance(envelope, CiphertextEnvelope) or envelope.scheme != NAME:
        raise InvalidCiphertextError("envelope_validation")
    nonce = require_bytes(envelope.nonce, "nonce")
    ciphertext = require_bytes(envelope.ciphertext, "ciphertext")
    tag = require_bytes(envelope.tag, "tag")
    if len(nonce) != NONCE_BYTES or len(tag) != TAG_BYTES:
        raise InvalidCiphertextError("envelope_validation")
    if envelope.iv is not None or envelope.mac is not None:
        raise InvalidCiphertextError("envelope_validation")
    try:
        return ChaCha20Poly1305(key).decrypt(nonce, ciphertext + tag, _AAD)
    except (InvalidTag, ValueError) as error:
        raise InvalidCiphertextError("authentication") from error
