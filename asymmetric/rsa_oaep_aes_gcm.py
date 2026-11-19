"""RSA-OAEP key wrapping with AES-256-GCM payload protection."""

from __future__ import annotations

import secrets

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from asymmetric.common import (
    AES_KEY_BYTES,
    GCM_NONCE_BYTES,
    RSA_SCHEME,
    DecryptionOutcome,
    HybridEnvelope,
    envelope_aad,
    exception_category,
    public_decrypt,
    require_bytes,
    validate_common_envelope,
)


OAEP_LABEL = b"COSC2539-HYBRID-v1/RSA-OAEP-AES-256-GCM"


def generate_keypair(key_size: int = 3072) -> tuple[rsa.RSAPrivateKey, rsa.RSAPublicKey]:
    """Generate the long-term recipient key pair outside message timings."""
    if key_size < 2048 or key_size % 256:
        raise ValueError("RSA key_size must be at least 2048 and divisible by 256")
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=key_size)
    return private_key, private_key.public_key()


def encrypt(plaintext: bytes, recipient_public_key: rsa.RSAPublicKey) -> HybridEnvelope:
    if not isinstance(plaintext, bytes):
        raise TypeError("plaintext must be bytes")
    if not isinstance(recipient_public_key, rsa.RSAPublicKey):
        raise TypeError("recipient_public_key must be an RSA public key")
    if recipient_public_key.key_size < 2048:
        raise ValueError("RSA recipient key must be at least 2048 bits")

    session_key = AESGCM.generate_key(bit_length=AES_KEY_BYTES * 8)
    nonce = secrets.token_bytes(GCM_NONCE_BYTES)
    aad_envelope = HybridEnvelope(RSA_SCHEME, nonce, b"", b"")
    encrypted = AESGCM(session_key).encrypt(nonce, plaintext, envelope_aad(aad_envelope))
    ciphertext, tag = encrypted[:-16], encrypted[-16:]
    wrapped_key = recipient_public_key.encrypt(
        session_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=OAEP_LABEL,
        ),
    )
    return HybridEnvelope(
        scheme=RSA_SCHEME,
        nonce=nonce,
        ciphertext=ciphertext,
        tag=tag,
        wrapped_key=wrapped_key,
    )


def attempt_decrypt(
    envelope: HybridEnvelope, recipient_private_key: rsa.RSAPrivateKey
) -> DecryptionOutcome:
    outcome = DecryptionOutcome(session_key_unwrapped=False)
    stage = "envelope_validation"
    try:
        validate_common_envelope(envelope, RSA_SCHEME)
        if not isinstance(recipient_private_key, rsa.RSAPrivateKey):
            raise ValueError("recipient private key is invalid")
        require_bytes(envelope.wrapped_key, "wrapped_key")
        if not envelope.wrapped_key:
            raise ValueError("wrapped_key must not be empty")

        stage = "rsa_oaep_unwrap"
        session_key = recipient_private_key.decrypt(
            envelope.wrapped_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=OAEP_LABEL,
            ),
        )
        if len(session_key) != AES_KEY_BYTES:
            raise ValueError("unwrapped AES key has an invalid length")
        outcome.session_key_unwrapped = True

        stage = "aes_gcm_authentication"
        outcome.aes_gcm_verification_reached = True
        plaintext = AESGCM(session_key).decrypt(
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


def decrypt(envelope: HybridEnvelope, recipient_private_key: rsa.RSAPrivateKey) -> bytes:
    return public_decrypt(attempt_decrypt(envelope, recipient_private_key))
