"""Shared envelope and result types for asymmetric hybrid encryption."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any


ENVELOPE_VERSION = 1
AES_KEY_BYTES = 32
GCM_NONCE_BYTES = 12
GCM_TAG_BYTES = 16
HKDF_SALT_BYTES = 32

RSA_SCHEME = "RSA-OAEP-SHA256+AES-256-GCM"
ECDH_SCHEME = "ECDH-P256-HKDF-SHA256+AES-256-GCM"
X25519_SCHEME = "X25519-HKDF-SHA256+AES-256-GCM"


@dataclass(frozen=True)
class HybridEnvelope:
    """In-memory envelope. Secret key material is never stored in this object."""

    scheme: str
    nonce: bytes
    ciphertext: bytes
    tag: bytes
    wrapped_key: bytes | None = None
    salt: bytes | None = None
    ephemeral_public_key: bytes | None = None
    version: int = ENVELOPE_VERSION


@dataclass
class DecryptionOutcome:
    """Internal decryption trace; callers must not persist ``plaintext``."""

    accepted: bool = False
    plaintext: bytes | None = None
    failure_stage: str | None = None
    exception_category: str | None = None
    internal_exception_type: str | None = None
    session_key_unwrapped: bool | None = None
    key_agreement_completed: bool | None = None
    hkdf_completed: bool | None = None
    aes_gcm_verification_reached: bool = False
    plaintext_released: bool = False


class HybridDecryptionError(Exception):
    """Normalized public decryption failure without backend-specific detail."""


def require_bytes(value: Any, field: str) -> bytes:
    if not isinstance(value, bytes):
        raise ValueError(f"{field} must be bytes")
    return value


def envelope_aad(envelope: HybridEnvelope) -> bytes:
    """Create unambiguous, versioned AAD that binds public envelope metadata."""
    scheme = envelope.scheme.encode("ascii")
    fields = (
        scheme,
        envelope.salt or b"",
        envelope.ephemeral_public_key or b"",
    )
    encoded = bytearray(b"COSC2539-HYBRID\x00")
    encoded.extend(envelope.version.to_bytes(2, "big"))
    for field in fields:
        encoded.extend(len(field).to_bytes(4, "big"))
        encoded.extend(field)
    return bytes(encoded)


def validate_common_envelope(envelope: HybridEnvelope, expected_scheme: str) -> None:
    if not isinstance(envelope, HybridEnvelope):
        raise ValueError("envelope has an invalid type")
    if envelope.version != ENVELOPE_VERSION:
        raise ValueError("unsupported envelope version")
    if envelope.scheme != expected_scheme:
        raise ValueError("envelope scheme does not match the decryptor")
    require_bytes(envelope.nonce, "nonce")
    require_bytes(envelope.ciphertext, "ciphertext")
    require_bytes(envelope.tag, "tag")
    if len(envelope.nonce) != GCM_NONCE_BYTES:
        raise ValueError("nonce must be 12 bytes")
    if len(envelope.tag) != GCM_TAG_BYTES:
        raise ValueError("tag must be 16 bytes")


def exception_category(error: BaseException) -> str:
    """Return a stable coarse category while retaining detail in process memory."""
    name = type(error).__name__
    if name == "InvalidTag":
        return "authentication_failed"
    if isinstance(error, ValueError):
        return "invalid_input_or_key"
    if isinstance(error, TypeError):
        return "invalid_type"
    if name in {"InvalidKey", "UnsupportedAlgorithm"}:
        return "invalid_key_or_algorithm"
    return "cryptographic_operation_failed"


def public_decrypt(outcome: DecryptionOutcome) -> bytes:
    """Return authenticated plaintext or raise one normalized public error."""
    if not outcome.accepted or outcome.plaintext is None:
        raise HybridDecryptionError("hybrid envelope decryption failed") from None
    return outcome.plaintext
