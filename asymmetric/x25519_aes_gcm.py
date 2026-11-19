"""Ephemeral X25519, HKDF-SHA256, and AES-256-GCM hybrid encryption."""

from __future__ import annotations

import secrets

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from asymmetric.common import (
    AES_KEY_BYTES,
    GCM_NONCE_BYTES,
    HKDF_SALT_BYTES,
    X25519_SCHEME,
    DecryptionOutcome,
    HybridEnvelope,
    envelope_aad,
    exception_category,
    public_decrypt,
    require_bytes,
    validate_common_envelope,
)


HKDF_INFO = b"COSC2539-HYBRID-v1/X25519-AES-256-GCM"


def generate_keypair() -> tuple[x25519.X25519PrivateKey, x25519.X25519PublicKey]:
    private_key = x25519.X25519PrivateKey.generate()
    return private_key, private_key.public_key()


def _serialize_public_key(public_key: x25519.X25519PublicKey) -> bytes:
    return public_key.public_bytes(
        serialization.Encoding.Raw,
        serialization.PublicFormat.Raw,
    )


def _derive_key(shared_secret: bytes, salt: bytes) -> bytes:
    return HKDF(
        algorithm=hashes.SHA256(),
        length=AES_KEY_BYTES,
        salt=salt,
        info=HKDF_INFO,
    ).derive(shared_secret)


def encrypt(
    plaintext: bytes, recipient_public_key: x25519.X25519PublicKey
) -> HybridEnvelope:
    if not isinstance(plaintext, bytes):
        raise TypeError("plaintext must be bytes")
    if not isinstance(recipient_public_key, x25519.X25519PublicKey):
        raise TypeError("recipient_public_key must be an X25519 public key")

    ephemeral_private_key = x25519.X25519PrivateKey.generate()
    ephemeral_public_bytes = _serialize_public_key(ephemeral_private_key.public_key())
    salt = secrets.token_bytes(HKDF_SALT_BYTES)
    shared_secret = ephemeral_private_key.exchange(recipient_public_key)
    aes_key = _derive_key(shared_secret, salt)
    nonce = secrets.token_bytes(GCM_NONCE_BYTES)
    aad_envelope = HybridEnvelope(
        scheme=X25519_SCHEME,
        nonce=nonce,
        ciphertext=b"",
        tag=b"",
        salt=salt,
        ephemeral_public_key=ephemeral_public_bytes,
    )
    encrypted = AESGCM(aes_key).encrypt(nonce, plaintext, envelope_aad(aad_envelope))
    return HybridEnvelope(
        scheme=X25519_SCHEME,
        nonce=nonce,
        ciphertext=encrypted[:-16],
        tag=encrypted[-16:],
        salt=salt,
        ephemeral_public_key=ephemeral_public_bytes,
    )


def attempt_decrypt(
    envelope: HybridEnvelope, recipient_private_key: x25519.X25519PrivateKey
) -> DecryptionOutcome:
    outcome = DecryptionOutcome(key_agreement_completed=False, hkdf_completed=False)
    stage = "envelope_validation"
    try:
        validate_common_envelope(envelope, X25519_SCHEME)
        if not isinstance(recipient_private_key, x25519.X25519PrivateKey):
            raise ValueError("recipient private key is invalid")
        require_bytes(envelope.salt, "salt")
        require_bytes(envelope.ephemeral_public_key, "ephemeral_public_key")
        if len(envelope.salt) != HKDF_SALT_BYTES:
            raise ValueError("HKDF salt must be 32 bytes")

        stage = "public_key_parse"
        if len(envelope.ephemeral_public_key) != 32:
            raise ValueError("X25519 public keys must be 32 bytes")
        ephemeral_public_key = x25519.X25519PublicKey.from_public_bytes(
            envelope.ephemeral_public_key
        )
        stage = "key_agreement"
        shared_secret = recipient_private_key.exchange(ephemeral_public_key)
        outcome.key_agreement_completed = True

        stage = "hkdf"
        aes_key = _derive_key(shared_secret, envelope.salt)
        outcome.hkdf_completed = True

        stage = "aes_gcm_authentication"
        outcome.aes_gcm_verification_reached = True
        plaintext = AESGCM(aes_key).decrypt(
            envelope.nonce,
            envelope.ciphertext + envelope.tag,
            envelope_aad(envelope),
        )
        outcome.accepted = True
        outcome.plaintext = plaintext
        outcome.plaintext_released = True
        return outcome
    except Exception as error:
        outcome.failure_stage = stage
        outcome.exception_category = exception_category(error)
        outcome.internal_exception_type = type(error).__name__
        return outcome


def decrypt(
    envelope: HybridEnvelope, recipient_private_key: x25519.X25519PrivateKey
) -> bytes:
    return public_decrypt(attempt_decrypt(envelope, recipient_private_key))
