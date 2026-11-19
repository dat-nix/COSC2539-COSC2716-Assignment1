"""Functional RQ2 outcomes and randomized-block RQ3 decryption timings."""

from __future__ import annotations

import argparse
import random
import time
from dataclasses import replace
from pathlib import Path

from symmetric.common import CiphertextEnvelope, InvalidCiphertextError
from symmetric.experiment_utils import (
    INPUT_SIZES,
    MEASURED_BLOCKS,
    WARMUP_ITERATIONS,
    choose_seed,
    default_run_dir,
    derived_seed,
    environment_metadata,
    input_identifier,
    make_input,
    prepare_output_dir,
    utc_now,
    write_csv,
    write_json,
)
from symmetric.schemes import SCHEMES


VALID = "valid"
CIPHERTEXT_TAMPERED = "ciphertext_tampered"
AUTHENTICATION_TAMPERED = "authentication_data_tampered"
NONCE_IV_TAMPERED = "nonce_or_iv_tampered"
WRONG_KEY = "wrong_key"
MALFORMED = "malformed_envelope"
SCENARIOS = (
    VALID,
    CIPHERTEXT_TAMPERED,
    AUTHENTICATION_TAMPERED,
    NONCE_IV_TAMPERED,
    WRONG_KEY,
    MALFORMED,
)

RQ2_CSV_NAME = "symmetric_rq2_outcomes.csv"
RQ2_METADATA_NAME = "symmetric_rq2_metadata.json"
RQ3_CSV_NAME = "symmetric_rq3_verification.csv"
RQ3_METADATA_NAME = "symmetric_rq3_metadata.json"
LOG_NAME = "execution.log"

RQ2_FIELDS = (
    "Algorithm",
    "Input size in bytes",
    "Scenario",
    "Scenario detail",
    "Input identifier",
    "Expected accepted",
    "Accepted",
    "Expected failure stage",
    "Failure stage",
    "Exception category",
    "Authentication succeeded",
    "Plaintext released",
    "Outcome matched expectation",
)

RQ3_FIELDS = (
    "Algorithm",
    "Input size in bytes",
    "Scenario",
    "Block ID",
    "Randomized position within block",
    "Repetition number",
    "Input identifier",
    "Envelope identifier",
    "Previous condition ID",
    "Previous algorithm",
    "Previous input size in bytes",
    "Previous scenario",
    "Measurement start UTC",
    "Measurement start monotonic seconds",
    "Measurement end monotonic seconds",
    "Total attempted decryption time in seconds",
    "Accepted",
    "Authentication succeeded",
    "Plaintext released",
    "Failure category",
)


def _flip(value: bytes) -> bytes:
    if not value:
        raise ValueError("cannot mutate an empty envelope field")
    return bytes((value[0] ^ 1,)) + value[1:]


def mutate_envelope(
    algorithm: str, envelope: CiphertextEnvelope, scenario: str
) -> CiphertextEnvelope:
    """Build controlled invalid envelopes before any RQ3 timer starts."""
    if scenario == VALID or scenario == WRONG_KEY:
        return envelope
    if scenario == CIPHERTEXT_TAMPERED:
        return replace(envelope, ciphertext=_flip(envelope.ciphertext or b""))
    if scenario == AUTHENTICATION_TAMPERED:
        if envelope.mac is not None:
            return replace(envelope, mac=_flip(envelope.mac))
        return replace(envelope, tag=_flip(envelope.tag or b""))
    if scenario == NONCE_IV_TAMPERED:
        if envelope.iv is not None:
            return replace(envelope, iv=_flip(envelope.iv))
        return replace(envelope, nonce=_flip(envelope.nonce or b""))
    if scenario == MALFORMED:
        return replace(envelope, ciphertext=None)
    raise ValueError(f"unknown scenario {scenario!r} for {algorithm}")


def _expected_failure_stage(algorithm: str, scenario: str) -> str:
    if scenario == VALID:
        return ""
    if scenario == MALFORMED:
        return "envelope_validation"
    return "authentication"


def _condition_id(condition: tuple[str, int, str]) -> str:
    return "|".join(map(str, condition))


def _timed_decrypt(scheme, envelope: CiphertextEnvelope, key):
    """Time only the public decrypt call, including its rejection exception path."""
    start = time.perf_counter()
    try:
        plaintext = scheme.decrypt(envelope, key)
    except InvalidCiphertextError as error:
        end = time.perf_counter()
        return end - start, start, end, None, False, False, error._failure_stage
    end = time.perf_counter()
    return end - start, start, end, plaintext, True, True, ""


def rq3_conditions(
    input_sizes: tuple[int, ...] = INPUT_SIZES,
) -> tuple[tuple[str, int, str], ...]:
    return tuple(
        (scheme.name, size, scenario)
        for scheme in SCHEMES
        for size in input_sizes
        for scenario in SCENARIOS
    )


def rq3_block_orders(
    seed: int,
    blocks: int = MEASURED_BLOCKS,
    input_sizes: tuple[int, ...] = INPUT_SIZES,
) -> list[list[tuple[str, int, str]]]:
    if blocks <= 0 or not input_sizes or len(set(input_sizes)) != len(input_sizes):
        raise ValueError("blocks and unique input sizes must be positive")
    base = list(rq3_conditions(input_sizes))
    orders = []
    for block in range(1, blocks + 1):
        order = base.copy()
        random.Random(derived_seed(seed, "rq3-measured-order", block)).shuffle(order)
        orders.append(order)
    return orders


def run_rq2(
    output_dir: str | Path | None = None,
    *,
    seed: int | None = None,
    input_sizes: tuple[int, ...] = INPUT_SIZES,
) -> tuple[Path, Path]:
    """Run functional tamper checks; these are outcomes, not attack probabilities."""
    if not input_sizes or any(size <= 0 for size in input_sizes) or len(set(input_sizes)) != len(input_sizes):
        raise ValueError("input_sizes must be unique positive sizes")
    seed_value, seed_source = choose_seed(seed)
    target = prepare_output_dir(
        output_dir or default_run_dir("rq2"), (RQ2_CSV_NAME, RQ2_METADATA_NAME, LOG_NAME)
    )
    keys = {scheme.name: scheme.generate_key() for scheme in SCHEMES}
    scheme_by_name = {scheme.name: scheme for scheme in SCHEMES}
    payloads = {
        size: make_input(size, derived_seed(seed_value, "rq2-input", size))
        for size in input_sizes
    }
    identifiers = {size: input_identifier(payload) for size, payload in payloads.items()}
    envelopes = {
        (scheme.name, size): scheme.encrypt(payloads[size], keys[scheme.name])
        for scheme in SCHEMES
        for size in input_sizes
    }
    cases = [
        (scheme.name, size, scenario)
        for scheme in SCHEMES
        for size in input_sizes
        for scenario in SCENARIOS
    ]
    random.Random(derived_seed(seed_value, "rq2-case-order")).shuffle(cases)
    rows = []
    for algorithm, size, scenario in cases:
        scheme = scheme_by_name[algorithm]
        envelope = mutate_envelope(algorithm, envelopes[(algorithm, size)], scenario)
        attempt_key = keys[algorithm]
        if scenario == WRONG_KEY:
            attempt_key = scheme.generate_key()
        expected_accepted = scenario == VALID
        expected_stage = _expected_failure_stage(algorithm, scenario)
        try:
            plaintext = scheme.decrypt(envelope, attempt_key)
            accepted = True
            released = plaintext == payloads[size]
            failure_stage = ""
            exception_category = ""
            del plaintext
        except InvalidCiphertextError as error:
            accepted = False
            released = False
            failure_stage = error._failure_stage
            exception_category = type(error).__name__
        matched = accepted == expected_accepted and released == expected_accepted and failure_stage == expected_stage
        if not matched:
            raise RuntimeError(f"RQ2 outcome did not match expectation: {algorithm}/{size}/{scenario}")
        rows.append(
            {
                "Algorithm": algorithm,
                "Input size in bytes": size,
                "Scenario": scenario,
                "Scenario detail": _scenario_detail(algorithm, scenario),
                "Input identifier": identifiers[size],
                "Expected accepted": expected_accepted,
                "Accepted": accepted,
                "Expected failure stage": expected_stage,
                "Failure stage": failure_stage,
                "Exception category": exception_category,
                "Authentication succeeded": accepted,
                "Plaintext released": released,
                "Outcome matched expectation": matched,
            }
        )

    raw_path = target / RQ2_CSV_NAME
    metadata_path = target / RQ2_METADATA_NAME
    write_csv(raw_path, RQ2_FIELDS, rows)
    write_json(
        metadata_path,
        {
            "experiment": "symmetric RQ2 functional adversarial outcomes",
            "status": "complete",
            "random_seed": seed_value,
            "random_seed_source": seed_source,
            "input_sizes_bytes": list(input_sizes),
            "algorithms": [scheme.name for scheme in SCHEMES],
            "scenarios": list(SCENARIOS),
            "expected_case_count": len(cases),
            "case_count": len(rows),
            "timing": "not measured",
            "key_material_written": False,
            "public_error_behavior": "All malformed/authentication failures use the same public exception type and message; private failure-stage labels are recorded only in these local controlled experiment outputs.",
            "environment": environment_metadata(),
            "created_utc": utc_now(),
        },
    )
    (target / LOG_NAME).write_text(
        f"Completed at {utc_now()}\nFunctional cases: {len(rows)}\n", encoding="utf-8"
    )
    return raw_path, metadata_path


def _scenario_detail(algorithm: str, scenario: str) -> str:
    if scenario == CIPHERTEXT_TAMPERED:
        return "first ciphertext byte changed"
    if scenario == AUTHENTICATION_TAMPERED:
        return "MAC byte changed" if "CBC" in algorithm else "authentication tag byte changed"
    if scenario == NONCE_IV_TAMPERED:
        return "CBC IV byte changed" if "CBC" in algorithm else "AEAD nonce byte changed"
    if scenario == WRONG_KEY:
        return "different random key material of valid length"
    if scenario == MALFORMED:
        return "ciphertext field missing (None)"
    return "original envelope and key"


def run_rq3(
    output_dir: str | Path | None = None,
    *,
    seed: int | None = None,
    blocks: int = MEASURED_BLOCKS,
    input_sizes: tuple[int, ...] = INPUT_SIZES,
) -> tuple[Path, Path]:
    """Measure complete decryption attempts in randomized matched blocks."""
    if blocks <= 0 or not input_sizes or any(size <= 0 for size in input_sizes):
        raise ValueError("blocks and input sizes must be positive")
    if len(set(input_sizes)) != len(input_sizes):
        raise ValueError("input_sizes must not contain duplicates")
    seed_value, seed_source = choose_seed(seed)
    target = prepare_output_dir(
        output_dir or default_run_dir("rq3"), (RQ3_CSV_NAME, RQ3_METADATA_NAME, LOG_NAME)
    )
    keys = {scheme.name: scheme.generate_key() for scheme in SCHEMES}
    scheme_by_name = {scheme.name: scheme for scheme in SCHEMES}
    orders = rq3_block_orders(seed_value, blocks, input_sizes)
    base_conditions = rq3_conditions(input_sizes)
    rows = []

    for block_id, order in enumerate(orders, start=1):
        payloads = {
            size: make_input(size, derived_seed(seed_value, "rq3-input", block_id, size))
            for size in input_sizes
        }
        identifiers = {size: input_identifier(payload) for size, payload in payloads.items()}
        envelopes = {
            (scheme.name, size): scheme.encrypt(payloads[size], keys[scheme.name])
            for scheme in SCHEMES
            for size in input_sizes
        }
        variants = {
            (algorithm, size, scenario): mutate_envelope(
                algorithm, envelopes[(algorithm, size)], scenario
            )
            for algorithm, size, scenario in base_conditions
        }
        wrong_keys = {
            (scheme.name, size): scheme.generate_key()
            for scheme in SCHEMES
            for size in input_sizes
        }

        warmups = list(base_conditions) * WARMUP_ITERATIONS
        random.Random(derived_seed(seed_value, "rq3-warmup-order", block_id)).shuffle(warmups)
        for algorithm, size, scenario in warmups:
            scheme = scheme_by_name[algorithm]
            attempt_key = wrong_keys[(algorithm, size)] if scenario == WRONG_KEY else keys[algorithm]
            try:
                warmup_result = scheme.decrypt(variants[(algorithm, size, scenario)], attempt_key)
            except InvalidCiphertextError:
                if scenario == VALID:
                    raise RuntimeError("valid RQ3 warm-up was rejected")
            else:
                if scenario != VALID:
                    raise RuntimeError("invalid RQ3 warm-up was accepted")
                if warmup_result != payloads[size]:
                    raise RuntimeError("valid RQ3 warm-up did not recover its input")

        previous = ("", "", "")
        for position, (algorithm, size, scenario) in enumerate(order, start=1):
            scheme = scheme_by_name[algorithm]
            attempt_key = wrong_keys[(algorithm, size)] if scenario == WRONG_KEY else keys[algorithm]
            envelope = variants[(algorithm, size, scenario)]
            start_utc = utc_now()
            elapsed, start, end, plaintext, accepted, released, failure_stage = (
                _timed_decrypt(scheme, envelope, attempt_key)
            )

            expected_valid = scenario == VALID
            expected_stage = _expected_failure_stage(algorithm, scenario)
            if accepted != expected_valid or released != expected_valid or failure_stage != expected_stage:
                raise RuntimeError(f"unexpected RQ3 outcome: {algorithm}/{size}/{scenario}")
            if expected_valid and plaintext != payloads[size]:
                raise RuntimeError("valid RQ3 attempt did not recover the input")
            del plaintext
            previous_text = "|".join(map(str, previous)) if previous[0] else ""
            rows.append(
                {
                    "Algorithm": algorithm,
                    "Input size in bytes": size,
                    "Scenario": scenario,
                    "Block ID": block_id,
                    "Randomized position within block": position,
                    "Repetition number": block_id,
                    "Input identifier": identifiers[size],
                    "Envelope identifier": f"{block_id}:{algorithm}:{size}",
                    "Previous condition ID": previous_text,
                    "Previous algorithm": previous[0],
                    "Previous input size in bytes": previous[1],
                    "Previous scenario": previous[2],
                    "Measurement start UTC": start_utc,
                    "Measurement start monotonic seconds": start,
                    "Measurement end monotonic seconds": end,
                    "Total attempted decryption time in seconds": elapsed,
                    "Accepted": accepted,
                    "Authentication succeeded": accepted,
                    "Plaintext released": released,
                    "Failure category": failure_stage,
                }
            )
            previous = (algorithm, size, scenario)

    expected_count = blocks * len(base_conditions)
    if len(rows) != expected_count:
        raise RuntimeError(f"expected {expected_count} RQ3 rows, generated {len(rows)}")
    raw_path = target / RQ3_CSV_NAME
    metadata_path = target / RQ3_METADATA_NAME
    write_csv(raw_path, RQ3_FIELDS, rows)
    write_json(
        metadata_path,
        {
            "experiment": "symmetric RQ3 randomized-block decryption verification performance",
            "status": "complete",
            "random_seed": seed_value,
            "random_seed_source": seed_source,
            "input_sizes_bytes": list(input_sizes),
            "algorithms": [scheme.name for scheme in SCHEMES],
            "scenarios": list(SCENARIOS),
            "block_count": blocks,
            "conditions_per_block": len(base_conditions),
            "expected_measured_observations": expected_count,
            "measured_observations": len(rows),
            "warmup_iterations_per_condition": WARMUP_ITERATIONS,
            "warmups_in_raw_csv": False,
            "randomization": "All algorithm-size-scenario labels are uniformly intended to be permuted within each complete block using separately derived pseudo-random seeds; warm-ups are separately shuffled.",
            "input_generation": "Deterministic pseudo-random bytes generated per block and size outside timers and shared across algorithms.",
            "timing": "time.perf_counter surrounds the complete public decrypt call, including envelope validation, authentication, decryption, and CBC unpadding. Mutations, wrong-key creation, input generation, and envelope encryption are outside timers.",
            "analysis_caution": "Conditional within-block label swaps are exploratory: they require the randomized assignment approximation and no consequential carry-over/interference. Timing measures complete decryption attempts, not isolated authentication overhead.",
            "key_material_written": False,
            "environment": environment_metadata(),
            "created_utc": utc_now(),
        },
    )
    (target / LOG_NAME).write_text(
        f"Completed at {utc_now()}\nMeasured observations: {len(rows)}\n", encoding="utf-8"
    )
    return raw_path, metadata_path


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("experiment", choices=("rq2", "rq3"))
    parser.add_argument("--output-dir", type=Path, default=None)
    parser.add_argument("--seed", type=int, default=None)
    parser.add_argument("--blocks", type=int, default=MEASURED_BLOCKS)
    args = parser.parse_args()
    if args.experiment == "rq2":
        raw, metadata = run_rq2(args.output_dir, seed=args.seed)
    else:
        raw, metadata = run_rq3(args.output_dir, seed=args.seed, blocks=args.blocks)
    print(f"Raw observations: {raw}")
    print(f"Metadata: {metadata}")


if __name__ == "__main__":
    main()
