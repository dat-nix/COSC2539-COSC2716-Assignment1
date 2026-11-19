"""Ephemeral P-256 ECDH, HKDF-SHA256, and AES-256-GCM hybrid encryption."""

from __future__ import annotations

import secrets

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from asymmetric.common import (
    AES_KEY_BYTES,
    ECDH_SCHEME,
    GCM_NONCE_BYTES,
    HKDF_SALT_BYTES,
    DecryptionOutcome,
    HybridEnvelope,
    envelope_aad,
    exception_category,
    public_decrypt,
    require_bytes,
    validate_common_envelope,
)


HKDF_INFO = b"COSC2539-HYBRID-v1/ECDH-P256-AES-256-GCM"


def generate_keypair() -> tuple[ec.EllipticCurvePrivateKey, ec.EllipticCurvePublicKey]:
    private_key = ec.generate_private_key(ec.SECP256R1())
    return private_key, private_key.public_key()


def _serialize_public_key(public_key: ec.EllipticCurvePublicKey) -> bytes:
    return public_key.public_bytes(
        serialization.Encoding.X962,
        serialization.PublicFormat.UncompressedPoint,
    )


def _derive_key(shared_secret: bytes, salt: bytes) -> bytes:
    return HKDF(
        algorithm=hashes.SHA256(),
        length=AES_KEY_BYTES,
        salt=salt,
        info=HKDF_INFO,
    ).derive(shared_secret)


def encrypt(
    plaintext: bytes, recipient_public_key: ec.EllipticCurvePublicKey
) -> HybridEnvelope:
    if not isinstance(plaintext, bytes):
        raise TypeError("plaintext must be bytes")
    if not isinstance(recipient_public_key, ec.EllipticCurvePublicKey):
        raise TypeError("recipient_public_key must be a P-256 public key")
    if not isinstance(recipient_public_key.curve, ec.SECP256R1):
        raise ValueError("recipient public key must use P-256")

    ephemeral_private_key = ec.generate_private_key(ec.SECP256R1())
    ephemeral_public_bytes = _serialize_public_key(ephemeral_private_key.public_key())
    salt = secrets.token_bytes(HKDF_SALT_BYTES)
    shared_secret = ephemeral_private_key.exchange(ec.ECDH(), recipient_public_key)
    aes_key = _derive_key(shared_secret, salt)
    nonce = secrets.token_bytes(GCM_NONCE_BYTES)
    aad_envelope = HybridEnvelope(
        scheme=ECDH_SCHEME,
        nonce=nonce,
        ciphertext=b"",
        tag=b"",
        salt=salt,
        ephemeral_public_key=ephemeral_public_bytes,
    )
    encrypted = AESGCM(aes_key).encrypt(nonce, plaintext, envelope_aad(aad_envelope))
    return HybridEnvelope(
        scheme=ECDH_SCHEME,
        nonce=nonce,
        ciphertext=encrypted[:-16],
        tag=encrypted[-16:],
        salt=salt,
        ephemeral_public_key=ephemeral_public_bytes,
    )


def attempt_decrypt(
    envelope: HybridEnvelope, recipient_private_key: ec.EllipticCurvePrivateKey
) -> DecryptionOutcome:
    outcome = DecryptionOutcome(key_agreement_completed=False, hkdf_completed=False)
    stage = "envelope_validation"
    try:
        validate_common_envelope(envelope, ECDH_SCHEME)
        if not isinstance(recipient_private_key, ec.EllipticCurvePrivateKey):
            raise ValueError("recipient private key is invalid")
        if not isinstance(recipient_private_key.curve, ec.SECP256R1):
            raise ValueError("recipient private key must use P-256")
        require_bytes(envelope.salt, "salt")
        require_bytes(envelope.ephemeral_public_key, "ephemeral_public_key")
        if len(envelope.salt) != HKDF_SALT_BYTES:
            raise ValueError("HKDF salt must be 32 bytes")

        stage = "public_key_parse"
        ephemeral_public_key = ec.EllipticCurvePublicKey.from_encoded_point(
            ec.SECP256R1(), envelope.ephemeral_public_key
        )
        stage = "key_agreement"
        shared_secret = recipient_private_key.exchange(ec.ECDH(), ephemeral_public_key)
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
    envelope: HybridEnvelope, recipient_private_key: ec.EllipticCurvePrivateKey
) -> bytes:
    return public_decrypt(attempt_decrypt(envelope, recipient_private_key))
