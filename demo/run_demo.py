"""Fast, presentation-only demonstrations of all nine project constructions.

This module calls the repository implementations directly. Timings printed here
are live illustrative timings, not research measurements, and are never saved.
"""

from __future__ import annotations

import argparse
import hmac
import os
from pathlib import Path
import sys
import time
from dataclasses import replace
from typing import Callable

# Support both ``python demo/run_demo.py`` and ``python -m demo.run_demo``.
REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
if str(REPOSITORY_ROOT) not in sys.path:
    sys.path.insert(0, str(REPOSITORY_ROOT))

from cryptography.hazmat.primitives import serialization

from asymmetric import ecdh_p256_aes_gcm, rsa_oaep_aes_gcm, x25519_aes_gcm
from asymmetric.common import DecryptionOutcome
from hashing import blake2b_256, sha256, sha3_256
from symmetric import aes_cbc_hmac, aes_gcm, chacha20_poly1305
from symmetric.common import InvalidCiphertextError


PAYLOAD = (b"COSC2539|IIoT sensor frame|temperature=24.7|" * 24)[:1024]
HASH_PAYLOAD = PAYLOAD * 1024  # 1 MiB, within the measured size range.
WIDTH = 104
INTERACTIVE = False
USE_COLOR = False

_COLORS = {
    "cyan": "\033[96m",
    "green": "\033[92m",
    "red": "\033[91m",
    "yellow": "\033[93m",
    "blue": "\033[94m",
    "dim": "\033[2m",
    "bold": "\033[1m",
    "reset": "\033[0m",
}


def _paint(text: str, color: str) -> str:
    if not USE_COLOR:
        return text
    return f"{_COLORS[color]}{text}{_COLORS['reset']}"


def _banner(number: int, title: str, subtitle: str) -> None:
    border = "=" * WIDTH
    print("\n" + _paint(border, "blue"))
    print(_paint(f" {number}. {title}", "bold"))
    print(_paint(f"    {subtitle}", "dim"))
    print(_paint(border, "blue"))


def _step(number: int, total: int, title: str, detail: str) -> None:
    """Print one presenter-friendly stage without exposing secret material."""
    print(f"\n{_paint(f'[STEP {number}/{total}]', 'cyan')} {_paint(title, 'bold')}")
    print(f"             {_paint(detail, 'dim')}")
    if INTERACTIVE:
        try:
            input("             Press ENTER to execute this step... ")
        except EOFError:
            print("             Input closed; continuing without pauses.")


def _source_evidence(label: str, module: object, calls: str) -> None:
    """Show which project source is executed without dumping implementation code."""
    source_file = getattr(module, "__file__", None)
    if source_file is None:
        source_file = sys.modules[module.__module__].__file__  # type: ignore[attr-defined]
    source = Path(source_file).resolve()
    try:
        source = source.relative_to(REPOSITORY_ROOT)
    except ValueError:
        pass
    print(f"{_paint('[SOURCE]', 'blue')}     {label:<31} | {source} | {calls}")


def _mutation_evidence(target: str, original: bytes, modified: bytes, index: int = 0) -> None:
    """Display one controlled byte mutation without revealing keys or full envelopes."""
    print(
        f"{_paint('[MUTATION]', 'yellow')}   target={target} | byte_index={index} | "
        f"before={_paint(f'0x{original[index]:02x}', 'red')} | "
        f"after={_paint(f'0x{modified[index]:02x}', 'green')} | other_bytes=unchanged"
    )


def _security_summary(rows: tuple[tuple[str, str], ...]) -> None:
    """Print a compact evidence-to-security-service mapping."""
    print("\n" + _paint("+----------------------+--------------------------------------------------------------------------------+", "blue"))
    print(_paint("| Security property    | Evidence / boundary                                                            |", "blue"))
    print(_paint("+----------------------+--------------------------------------------------------------------------------+", "blue"))
    for property_name, evidence in rows:
        color = "yellow" if property_name == "Not provided" else "green"
        print(_paint(f"| {property_name:<20} | {evidence:<78} |", color))
    print(_paint("+----------------------+--------------------------------------------------------------------------------+", "blue"))


def _timed(call: Callable[[], object]) -> tuple[object, float]:
    start = time.perf_counter()
    result = call()
    return result, time.perf_counter() - start


def _duration(seconds: float) -> str:
    microseconds = seconds * 1_000_000
    return f"{microseconds / 1000:8.3f} ms" if microseconds >= 1000 else f"{microseconds:8.2f} us"


def _flip(value: bytes) -> bytes:
    if not value:
        raise ValueError("cannot alter an empty field")
    return bytes([value[0] ^ 1]) + value[1:]


def _line(status: str, name: str, detail: str, elapsed: float | None = None) -> None:
    timing = f" | time={_duration(elapsed)}" if elapsed is not None else ""
    color = "green" if status in ("[PASS]", "[MATCHED]") else "red" if status in ("[FAIL]", "[REJECTED]") else "yellow"
    print(f"{_paint(f'{status:<12}', color)} {name:<31} | {detail}{_paint(timing, 'dim')}")


def run_hashing_demo() -> None:
    """Show all digests and the trusted-reference boundary."""
    _banner(1, "HASHING", "1 MiB payload | 256-bit digests | live timings are illustrative")
    _step(1, 5, "Prepare the input", "Create one 1 MiB message; no timing includes input generation.")
    _source_evidence("All hashing algorithms", sha256, "sha256() | sha3_256() | blake2b_256()")
    print(f"[INPUT]      payload_bytes={len(HASH_PAYLOAD)} | preview={HASH_PAYLOAD[:16]!r}")
    _step(2, 5, "Retain trusted digests", "Hash the original input with each implementation and keep the result as trusted.")
    algorithms = (
        ("SHA-256", sha256),
        ("SHA3-256", sha3_256),
        ("BLAKE2b-256", blake2b_256),
    )
    tampered = _flip(HASH_PAYLOAD)
    results = []
    for name, digest_fn in algorithms:
        trusted, elapsed = _timed(lambda fn=digest_fn: fn(HASH_PAYLOAD))
        candidate = digest_fn(tampered)
        attacker_digest = digest_fn(tampered)
        trusted_match = hmac.compare_digest(candidate, trusted)
        recomputed_match = hmac.compare_digest(candidate, attacker_digest)
        results.append((name, trusted, elapsed, trusted_match, recomputed_match))

    for name, trusted, elapsed, _, _ in results:
        _line("[PASS]", name, f"digest={trusted.hex()} | bits={len(trusted) * 8}", elapsed)

    _step(3, 5, "Modify one input byte", "Recompute each digest and compare it with the retained trusted digest.")
    _mutation_evidence("input payload", HASH_PAYLOAD, tampered)
    print("[EXPECTED]   Modified input must not match the retained trusted digest.")
    for name, _, _, trusted_match, _ in results:
        _line("[MISMATCH]", "tampered vs trusted digest", f"accepted={trusted_match}")

    _step(4, 5, "Replace the digest as an attacker", "Compare the same modified data with a newly recomputed unkeyed digest.")
    for name, trusted, _, trusted_match, recomputed_match in results:
        _line("[MATCHED]", "tampered + attacker digest", f"accepted={recomputed_match}")
        if trusted_match or not recomputed_match or len(trusted) != 32:
            raise AssertionError(f"unexpected digest result for {name}")
    _step(5, 5, "Security conclusion", "Integrity checking needs a trusted digest; an unkeyed hash does not authenticate a sender.")
    _security_summary(
        (
            ("Integrity check", "3/3 modified inputs mismatched their retained trusted digests."),
            ("Trust boundary", "3/3 attacker-recomputed unkeyed digests matched modified inputs."),
            ("Not provided", "No confidentiality and no sender authentication from an unkeyed hash."),
        )
    )


def _symmetric_attempt(module: object, envelope: object, key: object) -> tuple[bytes | None, str, float]:
    start = time.perf_counter()
    try:
        plaintext = module.decrypt(envelope, key)  # type: ignore[attr-defined]
        return plaintext, "accepted", time.perf_counter() - start
    except InvalidCiphertextError as error:
        stage = error._failure_stage
        if stage == "authentication":
            stage = "mac_verification" if module is aes_cbc_hmac else "aead_authentication"
        return None, stage, time.perf_counter() - start


def run_symmetric_demo() -> None:
    """Exercise valid and invalid paths in all symmetric constructions."""
    _banner(2, "SYMMETRIC ENCRYPTION", "Fresh keys/nonces/IVs | no secret material displayed")
    _step(1, 5, "Select the real project implementations", "AES-GCM, ChaCha20-Poly1305, and CBC-HMAC are called directly.")
    schemes = (
        ("AES-256-GCM", aes_gcm),
        ("ChaCha20-Poly1305", chacha20_poly1305),
        ("AES-256-CBC + HMAC-SHA256", aes_cbc_hmac),
    )
    for name, module in schemes:
        _source_evidence(name, module, "generate_key() -> encrypt() -> decrypt()")
    state: dict[str, tuple[object, object, object]] = {}
    _step(2, 5, "Run the valid path", "Generate fresh keys/nonces, encrypt, authenticate, and decrypt the original payload.")
    for name, module in schemes:
        key = module.generate_key()
        envelope, encrypt_time = _timed(lambda m=module, k=key: m.encrypt(PAYLOAD, k))
        recovered, stage, decrypt_time = _symmetric_attempt(module, envelope, key)
        ok = recovered == PAYLOAD
        _line("[PASS]" if ok else "[FAIL]", name, f"round_trip={ok} | encrypt={_duration(encrypt_time)}", decrypt_time)
        if not ok or stage != "accepted":
            raise AssertionError(f"valid round trip failed for {name}")
        state[name] = (module, key, envelope)

    aes_module, aes_key, aes_env = state["AES-256-GCM"]
    chacha_module, chacha_key, chacha_env = state["ChaCha20-Poly1305"]
    cbc_module, cbc_key, cbc_env = state["AES-256-CBC + HMAC-SHA256"]
    cases = (
        ("AES-GCM ciphertext tamper", aes_module, replace(aes_env, ciphertext=_flip(aes_env.ciphertext)), aes_key),
        ("AES-GCM malformed tag", aes_module, replace(aes_env, tag=aes_env.tag[:-1]), aes_key),
        ("ChaCha nonce tamper", chacha_module, replace(chacha_env, nonce=_flip(chacha_env.nonce)), chacha_key),
        ("ChaCha wrong key", chacha_module, chacha_env, chacha20_poly1305.generate_key()),
        ("CBC-HMAC MAC tamper", cbc_module, replace(cbc_env, mac=_flip(cbc_env.mac)), cbc_key),
        ("CBC-HMAC IV tamper", cbc_module, replace(cbc_env, iv=_flip(cbc_env.iv)), cbc_key),
        ("CBC-HMAC malformed envelope", cbc_module, replace(cbc_env, ciphertext=b""), cbc_key),
    )
    _step(3, 5, "Create adversarial inputs", "Change ciphertext, authentication data, nonce/IV, key material, or envelope structure.")
    altered_aes_ciphertext = _flip(aes_env.ciphertext)
    _mutation_evidence("AES-GCM ciphertext", aes_env.ciphertext, altered_aes_ciphertext)
    print("[EXPECTED]   Authentication failure; the decrypt API must release no plaintext.")
    for label, module, envelope, key in cases:
        plaintext, stage, elapsed = _symmetric_attempt(module, envelope, key)
        _line("[REJECTED]", label, f"stage={stage} | plaintext={plaintext!r}", elapsed)
        if plaintext is not None or stage == "accepted":
            raise AssertionError(f"invalid symmetric case accepted: {label}")
    _step(4, 5, "Verify the failure boundary", "Every invalid case is rejected and releases no plaintext.")
    print("CBC-HMAC ordering: envelope validation -> MAC verification -> CBC decryption/unpadding.")
    _step(5, 5, "Security conclusion", "Confidentiality and integrity are enforced; unauthenticated plaintext is never released.")
    _security_summary(
        (
            ("Confidentiality", "Valid ciphertext decrypts only with the corresponding secret key."),
            ("Integrity", "7/7 modified, wrong-key, or malformed examples were rejected."),
            ("Plaintext safety", "Every shown invalid call released no plaintext."),
            ("Not provided", "A shared-key tag does not identify which key holder sent the message."),
        )
    )


def _attempt(function: Callable[..., DecryptionOutcome], envelope: object, key: object) -> tuple[DecryptionOutcome, float]:
    result, elapsed = _timed(lambda: function(envelope, key))
    return result, elapsed  # type: ignore[return-value]


def run_hybrid_demo() -> None:
    """Exercise valid and stage-distinct invalid hybrid envelopes."""
    _banner(3, "ASYMMETRIC-BASED HYBRID ENCRYPTION", "Public-key key handling + AES-256-GCM payload protection")
    _step(1, 5, "Select the real hybrid implementations", "RSA-OAEP key wrapping, P-256 ECDH, and X25519 are called directly.")
    schemes = (
        ("RSA-OAEP + AES-256-GCM", rsa_oaep_aes_gcm),
        ("ECDH P-256 + HKDF + AES-GCM", ecdh_p256_aes_gcm),
        ("X25519 + HKDF + AES-GCM", x25519_aes_gcm),
    )
    for name, module in schemes:
        _source_evidence(name, module, "generate_keypair() -> encrypt() -> attempt_decrypt()")
    state: dict[str, tuple[object, object, object]] = {}
    _step(2, 5, "Run the valid path", "Protect or derive a fresh AES key, then encrypt and authenticate the payload with GCM.")
    for name, module in schemes:
        private_key, public_key = module.generate_keypair()
        envelope, encrypt_time = _timed(lambda m=module, p=public_key: m.encrypt(PAYLOAD, p))
        outcome, decrypt_time = _attempt(module.attempt_decrypt, envelope, private_key)
        ok = outcome.accepted and outcome.plaintext == PAYLOAD
        _line("[PASS]" if ok else "[FAIL]", name, f"round_trip={ok} | encrypt={_duration(encrypt_time)}", decrypt_time)
        if not ok:
            raise AssertionError(f"valid hybrid round trip failed for {name}")
        state[name] = (module, private_key, envelope)

    rsa_module, rsa_private, rsa_env = state["RSA-OAEP + AES-256-GCM"]
    ec_module, ec_private, ec_env = state["ECDH P-256 + HKDF + AES-GCM"]
    x_module, x_private, x_env = state["X25519 + HKDF + AES-GCM"]
    _, replacement_ec_public = ecdh_p256_aes_gcm.generate_keypair()
    replacement_ec = replacement_ec_public.public_bytes(serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)
    _, replacement_x_public = x25519_aes_gcm.generate_keypair()
    replacement_x = replacement_x_public.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    cases = (
        ("Malformed RSA envelope", rsa_module, replace(rsa_env, nonce=rsa_env.nonce[:-1]), rsa_private, "envelope_validation"),
        ("RSA wrapped-key tamper", rsa_module, replace(rsa_env, wrapped_key=_flip(rsa_env.wrapped_key)), rsa_private, "rsa_oaep_unwrap"),
        ("RSA ciphertext tamper", rsa_module, replace(rsa_env, ciphertext=_flip(rsa_env.ciphertext)), rsa_private, "aes_gcm_authentication"),
        ("Replacement ECDH public key", ec_module, replace(ec_env, ephemeral_public_key=replacement_ec), ec_private, "aes_gcm_authentication"),
        ("ECDH tag tamper", ec_module, replace(ec_env, tag=_flip(ec_env.tag)), ec_private, "aes_gcm_authentication"),
        ("Replacement X25519 public key", x_module, replace(x_env, ephemeral_public_key=replacement_x), x_private, "aes_gcm_authentication"),
        ("X25519 ciphertext tamper", x_module, replace(x_env, ciphertext=_flip(x_env.ciphertext)), x_private, "aes_gcm_authentication"),
    )
    _step(3, 5, "Create adversarial envelopes", "Change common fields, wrapped/key-agreement material, ciphertext, or tags.")
    altered_wrapped_key = _flip(rsa_env.wrapped_key)
    _mutation_evidence("RSA-OAEP wrapped AES key", rsa_env.wrapped_key, altered_wrapped_key)
    print("[EXPECTED]   Rejection at the reached stage; no payload plaintext may be released.")
    for label, module, envelope, key, expected_stage in cases:
        outcome, elapsed = _attempt(module.attempt_decrypt, envelope, key)
        stage = outcome.failure_stage or "accepted"
        display_stage = "oaep_unwrap" if stage == "rsa_oaep_unwrap" else stage
        _line("[REJECTED]", label, f"stage={display_stage} | plaintext={outcome.plaintext!r}", elapsed)
        if outcome.accepted or outcome.plaintext is not None or outcome.plaintext_released:
            raise AssertionError(f"invalid hybrid case released plaintext: {label}")
        if outcome.failure_stage != expected_stage:
            raise AssertionError(f"{label}: expected {expected_stage}, got {outcome.failure_stage}")
    _step(4, 5, "Verify staged rejection", "Every invalid envelope is rejected at its reached stage and releases no plaintext.")
    print("Replacement public keys complete agreement + HKDF but derive the wrong AES key; GCM rejects.")
    _step(5, 5, "Security conclusion", "Recipient confidentiality/integrity only; no sender signature, replay defense, or static-key forward secrecy.")
    _security_summary(
        (
            ("Key handling", "RSA wraps an AES key; ECDH/X25519 agreement plus HKDF derives one."),
            ("Payload security", "AES-GCM protects confidentiality and ciphertext integrity."),
            ("Staged rejection", "7/7 modified or malformed examples failed without plaintext release."),
            ("Not provided", "No sender authentication, replay defense, or static-key forward secrecy."),
        )
    )


DEMOS = {"hashing": run_hashing_demo, "symmetric": run_symmetric_demo, "hybrid": run_hybrid_demo}


def _interactive_menu() -> None:
    """Offer a Linux-style guided menu for live presentation use."""
    options = {
        "1": ("hashing", run_hashing_demo),
        "2": ("symmetric", run_symmetric_demo),
        "3": ("hybrid", run_hybrid_demo),
    }
    while True:
        menu = (
            "\n"
            "+------------------------------------------------------------------------------------------------------+\n"
            "|                  CRYPTOGRAPHY UNDER ADVERSARIAL CONDITIONS - GUIDED DEMO                       |\n"
            "+------------------------------------------------------------------------------------------------------+\n"
            "|  [1] Hashing                 Integrity checking and the trusted-digest boundary                |\n"
            "|  [2] Symmetric encryption    Confidentiality, authentication, and tamper rejection             |\n"
            "|  [3] Hybrid encryption       Public-key key handling with AES-GCM payload protection           |\n"
            "|  [A] Run all three guided demonstrations                                                       |\n"
            "|  [Q] Quit                                                                                       |\n"
            "+------------------------------------------------------------------------------------------------------+"
        )
        print(_paint(menu, "cyan"))
        try:
            choice = input("Select a demonstration: ").strip().lower()
        except EOFError:
            print("\nInput closed. Exiting guided demo.")
            return

        if choice == "q":
            print("Guided demo closed. No benchmark results were written.")
            return
        if choice == "a":
            selected = tuple(DEMOS.items())
        elif choice in options:
            name, function = options[choice]
            selected = ((name, function),)
        else:
            print("Invalid selection. Enter 1, 2, 3, A, or Q.")
            continue

        for name, function in selected:
            started = time.perf_counter()
            function()
            print(f"\n[COMPLETE] {name} walkthrough finished in {_duration(time.perf_counter() - started)}.")

        try:
            input("\nPress ENTER to return to the main menu... ")
        except EOFError:
            return


def main() -> None:
    global INTERACTIVE, USE_COLOR
    parser = argparse.ArgumentParser(description="Run the fast COSC2539 presentation demo.")
    parser.add_argument("legacy_section", nargs="?", choices=tuple(DEMOS), help=argparse.SUPPRESS)
    parser.add_argument("--section", choices=tuple(DEMOS), help="run one section; default: run all")
    parser.add_argument(
        "--interactive",
        action="store_true",
        help="show a guided menu and pause before each explained step",
    )
    color_group = parser.add_mutually_exclusive_group()
    color_group.add_argument("--color", action="store_true", help="force ANSI colors")
    color_group.add_argument("--no-color", action="store_true", help="disable ANSI colors")
    args = parser.parse_args()
    selected = args.section or args.legacy_section
    INTERACTIVE = args.interactive
    USE_COLOR = args.color or (sys.stdout.isatty() and not args.no_color and "NO_COLOR" not in os.environ)
    if INTERACTIVE and selected is None:
        _interactive_menu()
        return
    start = time.perf_counter()
    if selected:
        DEMOS[selected]()
    else:
        demos = tuple(DEMOS.values())
        for index, demo in enumerate(demos):
            demo()
            if index < len(demos) - 1:
                print("\nNext section in 5 seconds (presentation pacing)...")
                time.sleep(5)
    print(f"\n{'-' * WIDTH}\nDemo complete | elapsed={_duration(time.perf_counter() - start)} | no benchmark results written")


if __name__ == "__main__":
    main()
