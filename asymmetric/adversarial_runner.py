"""RQ2 adversarial outcomes and RQ3 decryption-verification timings."""

from __future__ import annotations

import argparse
import random
import time
from dataclasses import replace
from datetime import datetime, timezone
from pathlib import Path

from cryptography.hazmat.primitives import serialization

from asymmetric import ecdh_p256_aes_gcm, rsa_oaep_aes_gcm, x25519_aes_gcm
from asymmetric.common import ECDH_SCHEME, RSA_SCHEME, X25519_SCHEME, HybridEnvelope
from asymmetric.experiment_utils import (
    DEFAULT_RSA_KEY_SIZE,
    INPUT_SIZES,
    MEASURED_BLOCKS,
    WARMUP_ITERATIONS,
    block_randomization_seeds,
    choose_seed,
    derived_seed,
    environment_metadata,
    input_identifier,
    make_input,
    prepare_output_dir,
    public_key_fingerprints,
    seed_metadata,
    utc_now,
    write_csv,
    write_json,
)
from asymmetric.schemes import SCHEMES, generate_recipient_keypairs


VALID = "valid"
CIPHERTEXT_TAMPERED = "ciphertext_tampered"
TAG_TAMPERED = "tag_tampered"
KEY_TAMPERED = "key_material_tampered"
MALFORMED = "malformed_envelope_or_public_key"
KEY_REPLACED = "valid_replacement_public_key"
MALFORMED_PUBLIC = "malformed_public_key"
MALFORMED_COMMON = "malformed_common_envelope_field"

RQ2_CSV_NAME = "asymmetric_rq2_outcomes.csv"
RQ2_METADATA_NAME = "asymmetric_rq2_metadata.json"
RQ3_CSV_NAME = "asymmetric_rq3_verification.csv"
RQ3_METADATA_NAME = "asymmetric_rq3_metadata.json"

OUTCOME_FIELDS = (
    "Scheme",
    "Input size in bytes",
    "Scenario",
    "Scenario detail",
    "Input identifier",
    "Block ID",
    "Randomized position within block",
    "Repetition number",
    "Previous condition ID",
    "Previous scheme",
    "Previous input size in bytes",
    "Previous scenario",
    "Accepted",
    "Failure stage",
    "Exception category",
    "Internal exception type",
    "Session key unwrapped",
    "Key agreement completed",
    "HKDF completed",
    "AES-GCM verification reached",
    "Plaintext released",
)

RQ3_FIELDS = (
    *OUTCOME_FIELDS[:12],
    "Measurement start UTC",
    "Measurement start monotonic seconds",
    "Measurement end monotonic seconds",
    "Total attempted decryption time in seconds",
    *OUTCOME_FIELDS[12:],
)


def rq3_conditions(input_sizes: tuple[int, ...] = INPUT_SIZES):
    scenarios = (VALID, CIPHERTEXT_TAMPERED, TAG_TAMPERED, KEY_TAMPERED, MALFORMED)
    return tuple(
        (scheme.name, size, scenario)
        for scheme in SCHEMES
        for size in input_sizes
        for scenario in scenarios
    )


def rq3_block_orders(
    seed: int,
    blocks: int = MEASURED_BLOCKS,
    input_sizes=INPUT_SIZES,
    randomization_seeds: list[int] | None = None,
):
    if blocks <= 0:
        raise ValueError("blocks must be positive")
    if randomization_seeds is not None and len(randomization_seeds) != blocks:
        raise ValueError("randomization_seeds must contain one seed per block")
    base = list(rq3_conditions(tuple(input_sizes)))
    orders = []
    for block_id in range(1, blocks + 1):
        order = base.copy()
        block_seed = (
            randomization_seeds[block_id - 1]
            if randomization_seeds is not None
            else derived_seed(seed, "rq3-block", block_id)
        )
        random.Random(block_seed).shuffle(order)
        orders.append(order)
    return orders


def _id(condition) -> str:
    return "|".join(str(part) for part in condition)


def _flip_first(data: bytes) -> bytes:
    if not data:
        raise ValueError("cannot tamper an empty field")
    return bytes([data[0] ^ 1]) + data[1:]


def _modified_envelope(scheme_name: str, base: HybridEnvelope, scenario: str) -> HybridEnvelope:
    if scenario == VALID:
        return base
    if scenario == CIPHERTEXT_TAMPERED:
        return replace(base, ciphertext=_flip_first(base.ciphertext))
    if scenario == TAG_TAMPERED:
        return replace(base, tag=_flip_first(base.tag))
    if scenario == MALFORMED_COMMON:
        return replace(base, nonce=b"short")
    if scenario == KEY_TAMPERED:
        if scheme_name == RSA_SCHEME:
            return replace(base, wrapped_key=_flip_first(base.wrapped_key or b""))
        if scheme_name == ECDH_SCHEME:
            _, other_public = ecdh_p256_aes_gcm.generate_keypair()
            replacement = other_public.public_bytes(
                serialization.Encoding.X962,
                serialization.PublicFormat.UncompressedPoint,
            )
            return replace(base, ephemeral_public_key=replacement)
        _, other_public = x25519_aes_gcm.generate_keypair()
        replacement = other_public.public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        )
        return replace(base, ephemeral_public_key=replacement)
    if scenario == KEY_REPLACED:
        if scheme_name == ECDH_SCHEME:
            _, other_public = ecdh_p256_aes_gcm.generate_keypair()
            replacement = other_public.public_bytes(
                serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint
            )
            return replace(base, ephemeral_public_key=replacement)
        if scheme_name == X25519_SCHEME:
            _, other_public = x25519_aes_gcm.generate_keypair()
            replacement = other_public.public_bytes(
                serialization.Encoding.Raw, serialization.PublicFormat.Raw
            )
            return replace(base, ephemeral_public_key=replacement)
        raise ValueError("RSA uses wrapped-key tampering, not public-key replacement")
    if scenario == MALFORMED_PUBLIC:
        if scheme_name == ECDH_SCHEME:
            return replace(base, ephemeral_public_key=b"\x04malformed")
        if scheme_name == X25519_SCHEME:
            return replace(base, ephemeral_public_key=b"\x00" * 31)
        raise ValueError("RSA has no ephemeral public key")
    raise ValueError(f"unsupported scenario: {scenario}")


def _case_matrix(input_sizes: tuple[int, ...]):
    cases = []
    for scheme in SCHEMES:
        for size in input_sizes:
            cases.extend(
                (scheme.name, size, scenario, scenario)
                for scenario in (VALID, CIPHERTEXT_TAMPERED, TAG_TAMPERED, MALFORMED_COMMON)
            )
            if scheme.name == RSA_SCHEME:
                cases.append((scheme.name, size, "wrapped_key_tampered", KEY_TAMPERED))
            else:
                cases.append((scheme.name, size, KEY_REPLACED, KEY_REPLACED))
                cases.append((scheme.name, size, MALFORMED_PUBLIC, MALFORMED_PUBLIC))
    return cases


def _outcome_row(scheme_name, size, scenario, detail, data, outcome, *, block=1, position=1, previous=None):
    previous = previous or ("", "", "")
    return {
        "Scheme": scheme_name,
        "Input size in bytes": size,
        "Scenario": scenario,
        "Scenario detail": detail,
        "Input identifier": input_identifier(data),
        "Block ID": block,
        "Randomized position within block": position,
        "Repetition number": block,
        "Previous condition ID": _id(previous) if previous[0] else "",
        "Previous scheme": previous[0],
        "Previous input size in bytes": previous[1],
        "Previous scenario": previous[2],
        "Accepted": outcome.accepted,
        "Failure stage": outcome.failure_stage or "",
        "Exception category": outcome.exception_category or "",
        "Internal exception type": outcome.internal_exception_type or "",
        "Session key unwrapped": outcome.session_key_unwrapped,
        "Key agreement completed": outcome.key_agreement_completed,
        "HKDF completed": outcome.hkdf_completed,
        "AES-GCM verification reached": outcome.aes_gcm_verification_reached,
        "Plaintext released": outcome.plaintext_released,
    }


def run_rq2(
    output_dir: str | Path,
    *,
    seed: int | None = None,
    input_sizes: tuple[int, ...] = INPUT_SIZES,
    rsa_key_size: int = DEFAULT_RSA_KEY_SIZE,
):
    """Record a functional adversarial matrix; this is not a timing benchmark."""
    if not input_sizes or any(size <= 0 for size in input_sizes):
        raise ValueError("input sizes must be positive")
    if len(set(input_sizes)) != len(input_sizes):
        raise ValueError("input_sizes must not contain duplicates")
    seed_value, seed_source = choose_seed(seed)
    target = prepare_output_dir(output_dir, (RQ2_CSV_NAME, RQ2_METADATA_NAME))
    keypairs = generate_recipient_keypairs(rsa_key_size)
    scheme_by_name = {scheme.name: scheme for scheme in SCHEMES}
    cases = _case_matrix(tuple(input_sizes))
    random.Random(derived_seed(seed_value, "rq2-case-order")).shuffle(cases)
    input_by_size = {
        size: make_input(size, derived_seed(seed_value, "rq2-input", size))
        for size in input_sizes
    }
    envelopes = {
        (scheme.name, size): scheme.encrypt(input_by_size[size], keypairs[scheme.name][1])
        for scheme in SCHEMES
        for size in input_sizes
    }
    rows = []
    for position, (scheme_name, size, label, mutation) in enumerate(cases, start=1):
        scheme = scheme_by_name[scheme_name]
        private_key = keypairs[scheme_name][0]
        envelope = _modified_envelope(
            scheme_name, envelopes[(scheme_name, size)], mutation
        )
        outcome = scheme.attempt_decrypt(envelope, private_key)
        if label == VALID:
            expected = input_by_size[size]
            if not outcome.accepted or outcome.plaintext != expected:
                raise RuntimeError("valid RQ2 envelope did not release the original plaintext")
        elif outcome.accepted or outcome.plaintext_released or outcome.plaintext is not None:
            raise RuntimeError(f"invalid RQ2 case released plaintext: {label}")
        outcome.plaintext = None
        rows.append(_outcome_row(scheme_name, size, label, mutation, input_by_size[size], outcome, position=position))

    csv_path, metadata_path = target / RQ2_CSV_NAME, target / RQ2_METADATA_NAME
    write_csv(csv_path, OUTCOME_FIELDS, rows)
    write_json(metadata_path, {
        "experiment": "RQ2 asymmetric hybrid tampering and malformed-envelope outcomes",
        **seed_metadata(seed_value, seed_source),
        "randomization": "one pseudo-random functional case ordering; not used for inferential randomization",
        "case_count": len(rows),
        "input_sizes_bytes": list(input_sizes),
        "rsa_key_size_bits": rsa_key_size,
        "recipient_public_key_sha256_fingerprints": public_key_fingerprints(keypairs),
        "timing": "not measured; outcomes only",
        "environment": environment_metadata(),
        "created_utc": utc_now(),
    })
    return csv_path, metadata_path


def _rq3_variants(scheme_name, envelope):
    return {
        VALID: envelope,
        CIPHERTEXT_TAMPERED: _modified_envelope(scheme_name, envelope, CIPHERTEXT_TAMPERED),
        TAG_TAMPERED: _modified_envelope(scheme_name, envelope, TAG_TAMPERED),
        KEY_TAMPERED: _modified_envelope(scheme_name, envelope, KEY_TAMPERED),
        MALFORMED: (
            _modified_envelope(scheme_name, envelope, MALFORMED_COMMON)
            if scheme_name == RSA_SCHEME
            else _modified_envelope(scheme_name, envelope, MALFORMED_PUBLIC)
        ),
    }


def run_rq3(
    output_dir: str | Path,
    *,
    seed: int | None = None,
    blocks: int = MEASURED_BLOCKS,
    input_sizes: tuple[int, ...] = INPUT_SIZES,
    rsa_key_size: int = DEFAULT_RSA_KEY_SIZE,
):
    """Measure complete valid and invalid decryption attempts in randomized blocks."""
    if blocks <= 0 or not input_sizes or any(size <= 0 for size in input_sizes):
        raise ValueError("blocks and input sizes must be positive")
    if len(set(input_sizes)) != len(input_sizes):
        raise ValueError("input_sizes must not contain duplicates")

    seed_value, seed_source = choose_seed(seed)
    target = prepare_output_dir(output_dir, (RQ3_CSV_NAME, RQ3_METADATA_NAME))
    keypairs = generate_recipient_keypairs(rsa_key_size)
    scheme_by_name = {scheme.name: scheme for scheme in SCHEMES}
    block_seeds = block_randomization_seeds(seed_value, seed_source, blocks)
    orders = rq3_block_orders(seed_value, blocks, tuple(input_sizes), block_seeds)

    warmup_buffers = {
        size: make_input(size, derived_seed(seed_value, "rq3-warmup-input", size))
        for size in input_sizes
    }
    warmup_envelopes = {
        (scheme.name, size): scheme.encrypt(warmup_buffers[size], keypairs[scheme.name][1])
        for scheme in SCHEMES
        for size in input_sizes
    }
    warmup_cases = [
        (scheme.name, size, scenario)
        for scheme in SCHEMES
        for size in input_sizes
        for scenario in (VALID, CIPHERTEXT_TAMPERED, TAG_TAMPERED, KEY_TAMPERED, MALFORMED)
        for _ in range(WARMUP_ITERATIONS)
    ]
    random.Random(derived_seed(seed_value, "rq3-warmup-order")).shuffle(warmup_cases)
    for scheme_name, size, scenario in warmup_cases:
        scheme = scheme_by_name[scheme_name]
        envelope = _rq3_variants(scheme_name, warmup_envelopes[(scheme_name, size)])[scenario]
        scheme.attempt_decrypt(envelope, keypairs[scheme_name][0])

    rows = []
    for block_id, order in enumerate(orders, start=1):
        buffers = {
            size: make_input(size, derived_seed(seed_value, "rq3-input", block_id, size))
            for size in input_sizes
        }
        identifiers = {size: input_identifier(data) for size, data in buffers.items()}
        envelopes = {
            (scheme.name, size): scheme.encrypt(buffers[size], keypairs[scheme.name][1])
            for scheme in SCHEMES
            for size in input_sizes
        }
        previous = None
        for position, condition in enumerate(order, start=1):
            scheme_name, size, scenario = condition
            scheme = scheme_by_name[scheme_name]
            envelope = _rq3_variants(scheme_name, envelopes[(scheme_name, size)])[scenario]
            start_utc = datetime.now(timezone.utc).isoformat()
            start = time.perf_counter()
            outcome = scheme.attempt_decrypt(envelope, keypairs[scheme_name][0])
            end = time.perf_counter()
            if scenario == VALID:
                if not outcome.accepted or outcome.plaintext != buffers[size]:
                    raise RuntimeError("valid RQ3 decryption failed")
            elif outcome.accepted or outcome.plaintext_released or outcome.plaintext is not None:
                raise RuntimeError(f"invalid RQ3 scenario released plaintext: {scenario}")
            outcome.plaintext = None
            previous_parts = previous or ("", "", "")
            row = _outcome_row(
                scheme_name, size, scenario, scenario, buffers[size], outcome,
                block=block_id, position=position, previous=previous_parts,
            )
            row["Input identifier"] = identifiers[size]
            row["Measurement start UTC"] = start_utc
            row["Measurement start monotonic seconds"] = start
            row["Measurement end monotonic seconds"] = end
            row["Total attempted decryption time in seconds"] = end - start
            rows.append(row)
            previous = condition

    csv_path, metadata_path = target / RQ3_CSV_NAME, target / RQ3_METADATA_NAME
    write_csv(csv_path, RQ3_FIELDS, rows)
    write_json(metadata_path, {
        "experiment": "RQ3 asymmetric hybrid matched verification timings",
        **seed_metadata(seed_value, seed_source),
        "randomization": "one Python random.Random shuffle per block, with an independently drawn 256-bit OS seed for each block when the root seed source is OS entropy",
        "block_randomization_seeds": block_seeds,
        "block_count": blocks,
        "conditions_per_block": len(rq3_conditions(tuple(input_sizes))),
        "expected_measured_observations": blocks * len(rq3_conditions(tuple(input_sizes))),
        "warmup_iterations_per_condition": WARMUP_ITERATIONS,
        "scenario_order": [VALID, CIPHERTEXT_TAMPERED, TAG_TAMPERED, KEY_TAMPERED, MALFORMED],
        "input_sizes_bytes": list(input_sizes),
        "rsa_key_size_bits": rsa_key_size,
        "recipient_public_key_sha256_fingerprints": public_key_fingerprints(keypairs),
        "timing": "time.perf_counter around complete attempt_decrypt including rejection path",
        "randomization_test_eligibility": seed_source == "os_entropy",
        "environment": environment_metadata(),
        "created_utc": utc_now(),
    })
    return csv_path, metadata_path


def main() -> None:
    parser = argparse.ArgumentParser(description="Run an asymmetric hybrid adversarial experiment.")
    subparsers = parser.add_subparsers(dest="experiment", required=True)
    for name in ("rq2", "rq3"):
        subparser = subparsers.add_parser(name)
        subparser.add_argument("--output-dir", type=Path, default=None)
        subparser.add_argument("--seed", type=int, default=None)
        if name == "rq3":
            subparser.add_argument("--blocks", type=int, default=MEASURED_BLOCKS)
        subparser.add_argument("--rsa-key-size", type=int, default=DEFAULT_RSA_KEY_SIZE)
    args = parser.parse_args()
    default_dir = Path("results/asymmetric") / args.experiment / "runs" / "run_1"
    output_dir = args.output_dir or default_dir
    if args.experiment == "rq2":
        paths = run_rq2(output_dir, seed=args.seed, rsa_key_size=args.rsa_key_size)
    else:
        paths = run_rq3(
            output_dir, seed=args.seed, blocks=args.blocks, rsa_key_size=args.rsa_key_size
        )
    print(paths[0])
    print(paths[1])


if __name__ == "__main__":
    main()
