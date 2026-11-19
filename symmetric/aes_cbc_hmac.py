"""AES-256-CBC with PKCS#7 padding and Encrypt-then-MAC HMAC-SHA256."""

from __future__ import annotations

import hashlib
import hmac
import secrets

from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from symmetric.common import CiphertextEnvelope, InvalidCiphertextError, require_bytes


NAME = "AES-256-CBC+HMAC-SHA256"
KEY_BYTES = 32
IV_BYTES = 16
MAC_BYTES = 32
_MAC_CONTEXT = b"COSC2539:AES-256-CBC+HMAC-SHA256:Encrypt-then-MAC:v1\x00"


def generate_key() -> tuple[bytes, bytes]:
    """Return independent 256-bit AES and HMAC keys."""
    return secrets.token_bytes(KEY_BYTES), secrets.token_bytes(KEY_BYTES)


def _encrypt_cbc(plaintext: bytes, encryption_key: bytes, iv: bytes) -> bytes:
    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    padded = padder.update(plaintext) + padder.finalize()
    encryptor = Cipher(algorithms.AES(encryption_key), modes.CBC(iv)).encryptor()
    return encryptor.update(padded) + encryptor.finalize()


def _decrypt_cbc(ciphertext: bytes, encryption_key: bytes, iv: bytes) -> bytes:
    decryptor = Cipher(algorithms.AES(encryption_key), modes.CBC(iv)).decryptor()
    padded = decryptor.update(ciphertext) + decryptor.finalize()
    unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
    return unpadder.update(padded) + unpadder.finalize()


def _mac(authentication_key: bytes, iv: bytes, ciphertext: bytes) -> bytes:
    return hmac.new(
        authentication_key, _MAC_CONTEXT + iv + ciphertext, hashlib.sha256
    ).digest()


def encrypt(plaintext: bytes, key: tuple[bytes, bytes]) -> CiphertextEnvelope:
    """Pad, encrypt, then authenticate the IV and ciphertext."""
    if not isinstance(plaintext, bytes):
        raise TypeError("plaintext must be bytes")
    if (
        not isinstance(key, tuple)
        or len(key) != 2
        or any(not isinstance(part, bytes) or len(part) != KEY_BYTES for part in key)
    ):
        raise ValueError("CBC-HMAC requires two independent 32-byte keys")
    encryption_key, authentication_key = key
    iv = secrets.token_bytes(IV_BYTES)
    ciphertext = _encrypt_cbc(plaintext, encryption_key, iv)
    mac = _mac(authentication_key, iv, ciphertext)
    return CiphertextEnvelope(scheme=NAME, iv=iv, ciphertext=ciphertext, mac=mac)


def decrypt(envelope: CiphertextEnvelope, key: tuple[bytes, bytes]) -> bytes:
    """Verify Encrypt-then-MAC before CBC decryption or unpadding.

    Every malformed/authentication/decryption failure has the same public
    exception type and message. The private stage tag is for local experiment
    diagnostics only; applications should not expose it to remote callers.
    """
    if (
        not isinstance(key, tuple)
        or len(key) != 2
        or any(not isinstance(part, bytes) or len(part) != KEY_BYTES for part in key)
    ):
        raise InvalidCiphertextError("key_validation")
    if not isinstance(envelope, CiphertextEnvelope) or envelope.scheme != NAME:
        raise InvalidCiphertextError("envelope_validation")
    iv = require_bytes(envelope.iv, "iv")
    ciphertext = require_bytes(envelope.ciphertext, "ciphertext")
    supplied_mac = require_bytes(envelope.mac, "mac")
    if (
        len(iv) != IV_BYTES
        or len(supplied_mac) != MAC_BYTES
        or not ciphertext
        or len(ciphertext) % IV_BYTES != 0
        or envelope.nonce is not None
        or envelope.tag is not None
    ):
        raise InvalidCiphertextError("envelope_validation")

    _, authentication_key = key
    expected_mac = _mac(authentication_key, iv, ciphertext)
    if not hmac.compare_digest(expected_mac, supplied_mac):
        raise InvalidCiphertextError("authentication")

    encryption_key, _ = key
    try:
        return _decrypt_cbc(ciphertext, encryption_key, iv)
    except (ValueError, TypeError) as error:
        raise InvalidCiphertextError("decryption") from error
