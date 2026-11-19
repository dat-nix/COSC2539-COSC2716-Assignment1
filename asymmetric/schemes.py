"""Small dispatch table for the three approved hybrid encryption schemes."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable

from asymmetric import ecdh_p256_aes_gcm, rsa_oaep_aes_gcm, x25519_aes_gcm
from asymmetric.common import (
    ECDH_SCHEME,
    RSA_SCHEME,
    X25519_SCHEME,
    DecryptionOutcome,
    HybridEnvelope,
)


@dataclass(frozen=True)
class Scheme:
    name: str
    generate_keypair: Callable[..., tuple[Any, Any]]
    encrypt: Callable[[bytes, Any], HybridEnvelope]
    attempt_decrypt: Callable[[HybridEnvelope, Any], DecryptionOutcome]


SCHEMES = (
    Scheme(RSA_SCHEME, rsa_oaep_aes_gcm.generate_keypair, rsa_oaep_aes_gcm.encrypt, rsa_oaep_aes_gcm.attempt_decrypt),
    Scheme(ECDH_SCHEME, ecdh_p256_aes_gcm.generate_keypair, ecdh_p256_aes_gcm.encrypt, ecdh_p256_aes_gcm.attempt_decrypt),
    Scheme(X25519_SCHEME, x25519_aes_gcm.generate_keypair, x25519_aes_gcm.encrypt, x25519_aes_gcm.attempt_decrypt),
)

SCHEME_BY_NAME = {scheme.name: scheme for scheme in SCHEMES}


def generate_recipient_keypairs(rsa_key_size: int = 3072) -> dict[str, tuple[Any, Any]]:
    """Generate each long-term key pair once; callers keep private keys in memory."""
    return {
        RSA_SCHEME: rsa_oaep_aes_gcm.generate_keypair(rsa_key_size),
        ECDH_SCHEME: ecdh_p256_aes_gcm.generate_keypair(),
        X25519_SCHEME: x25519_aes_gcm.generate_keypair(),
    }
