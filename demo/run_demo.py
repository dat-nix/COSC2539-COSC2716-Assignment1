"""Run short cryptographic demonstrations using the project implementations."""

from __future__ import annotations

import argparse
import hmac
from dataclasses import replace

from asymmetric import rsa_oaep_aes_gcm
from asymmetric.common import RSA_SCHEME
from hashing import sha256
from symmetric import aes_gcm
from symmetric.common import InvalidCiphertextError


def run_hashing_demo() -> None:
    """Compare a modified message with a trusted and a recomputed digest."""
    original = b"valve=normal"
    modified = b"valve=manual"
    trusted_digest = sha256(original)
    modified_digest = sha256(modified)
    attacker_recomputed_digest = sha256(modified)
    trusted_match = hmac.compare_digest(modified_digest, trusted_digest)
    recomputed_match = hmac.compare_digest(modified_digest, attacker_recomputed_digest)

    print("=== Hashing integrity | SHA-256 ===")
    print(f"Original message: {original.decode('ascii')}")
    print(f"Trusted original digest: {trusted_digest.hex()}")
    print(f"Modified message: {modified.decode('ascii')}")
    print(f"Modified message digest: {modified_digest.hex()}")
    print(f"Attacker-recomputed digest: {attacker_recomputed_digest.hex()}")
    print(f"Modified data vs trusted digest: {'MATCH' if trusted_match else 'REJECTED'}")
    print(
        "Modified data vs attacker-recomputed digest: "
        f"{'MATCHES' if recomputed_match else 'REJECTED'}"
    )
    print("Interpretation: a matching unkeyed digest does not authenticate its source.")

    if trusted_match or not recomputed_match:
        raise AssertionError("SHA-256 demo produced an unexpected comparison result")


def run_symmetric_demo() -> None:
    """Round-trip with AES-GCM, then reject an altered authentication tag."""
    plaintext = b"COSC2539 demo: sensor status normal"
    key = aes_gcm.generate_key()
    envelope = aes_gcm.encrypt(plaintext, key)
    recovered = aes_gcm.decrypt(envelope, key)
    if recovered != plaintext:
        raise AssertionError("AES-GCM valid round trip did not recover the message")

    changed_tag = bytes([envelope.tag[0] ^ 1]) + envelope.tag[1:]
    invalid_envelope = replace(envelope, tag=changed_tag)
    released_plaintext: bytes | None = None
    rejected = False
    try:
        released_plaintext = aes_gcm.decrypt(invalid_envelope, key)
    except InvalidCiphertextError:
        rejected = True

    print("=== Symmetric authenticated encryption | AES-256-GCM ===")
    print("Key generated in memory; key, nonce, and ciphertext are not displayed.")
    print(f"Valid envelope: accepted; plaintext matches: {recovered == plaintext}")
    print(f"Tampered authentication tag: {'REJECTED' if rejected else 'ACCEPTED'}")
    print(f"Plaintext returned after failed authentication: {released_plaintext is not None}")

    if not rejected or released_plaintext is not None:
        raise AssertionError("AES-GCM tampering check did not reject without plaintext")


def run_hybrid_demo() -> None:
    """Use RSA-OAEP to wrap the session key and AES-GCM for the payload."""
    plaintext = b"COSC2539 demo: recipient-only key access"
    recipient_private_key, recipient_public_key = rsa_oaep_aes_gcm.generate_keypair()
    envelope = rsa_oaep_aes_gcm.encrypt(plaintext, recipient_public_key)
    valid = rsa_oaep_aes_gcm.attempt_decrypt(envelope, recipient_private_key)
    if not valid.accepted or valid.plaintext != plaintext or not valid.plaintext_released:
        raise AssertionError("RSA hybrid valid envelope did not return the original message")

    changed_tag = bytes([envelope.tag[0] ^ 1]) + envelope.tag[1:]
    invalid_envelope = replace(envelope, tag=changed_tag)
    invalid = rsa_oaep_aes_gcm.attempt_decrypt(
        invalid_envelope, recipient_private_key
    )

    print(f"=== Asymmetric-based hybrid encryption | {RSA_SCHEME} ===")
    print("Recipient RSA key pair generated in memory; no key material is displayed.")
    print("RSA-OAEP wraps a fresh AES key; AES-GCM encrypts and authenticates the payload.")
    print(f"Valid envelope: accepted; plaintext matches: {valid.plaintext == plaintext}")
    print(
        "Tampered authentication tag: "
        f"{'REJECTED' if not invalid.accepted else 'ACCEPTED'}; "
        f"failure stage: {invalid.failure_stage}"
    )
    print(f"Plaintext released after failure: {invalid.plaintext_released}")

    if invalid.accepted or invalid.plaintext_released or invalid.plaintext is not None:
        raise AssertionError("Hybrid tampering check did not reject without plaintext")
    if invalid.failure_stage != "aes_gcm_authentication":
        raise AssertionError("Tampered tag did not reach the expected GCM failure stage")


DEMOS = {
    "hashing": run_hashing_demo,
    "symmetric": run_symmetric_demo,
    "hybrid": run_hybrid_demo,
}


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Run a short demonstration without starting an experiment."
    )
    parser.add_argument("demo", choices=tuple(DEMOS))
    args = parser.parse_args()
    DEMOS[args.demo]()


if __name__ == "__main__":
    main()
