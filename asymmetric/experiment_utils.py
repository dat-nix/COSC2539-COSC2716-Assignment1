"""Shared, non-cryptographic experiment scheduling and output helpers."""

from __future__ import annotations

import csv
import hashlib
import importlib.metadata
import json
import platform
import random
import secrets
import ssl
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable


INPUT_SIZES = (1_024, 10_240, 102_400, 1_048_576, 10_485_760)
WARMUP_ITERATIONS = 5
MEASURED_BLOCKS = 30
DEFAULT_RSA_KEY_SIZE = 3072


def choose_seed(seed: int | None) -> tuple[int, str]:
    if seed is not None:
        return seed, "explicit"
    return secrets.randbits(256), "os_entropy"


def derived_seed(seed: int, *parts: object) -> int:
    material = ":".join((str(seed), *(str(part) for part in parts))).encode("utf-8")
    return int.from_bytes(hashlib.sha256(material).digest(), "big")


def block_randomization_seeds(seed: int, seed_source: str, blocks: int) -> list[int]:
    if blocks <= 0:
        raise ValueError("blocks must be positive")
    if seed_source == "os_entropy":
        seeds: list[int] = []
        used = set()
        while len(seeds) < blocks:
            candidate = secrets.randbits(256)
            if candidate not in used:
                used.add(candidate)
                seeds.append(candidate)
        return seeds
    return [derived_seed(seed, "block-randomization", block_id) for block_id in range(1, blocks + 1)]


def make_input(size_bytes: int, seed: int) -> bytes:
    if size_bytes < 0:
        raise ValueError("input size must not be negative")
    return random.Random(seed).randbytes(size_bytes)


def input_identifier(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def environment_metadata() -> dict:
    package_versions = {}
    for package in ("cryptography", "numpy", "scipy", "statsmodels", "pandas", "matplotlib"):
        try:
            package_versions[package] = importlib.metadata.version(package)
        except importlib.metadata.PackageNotFoundError:
            package_versions[package] = None
    return {
        "python": sys.version,
        "platform": platform.platform(),
        "processor": platform.processor(),
        "openssl": ssl.OPENSSL_VERSION,
        "packages": package_versions,
    }


def prepare_output_dir(output_dir: str | Path, names: Iterable[str]) -> Path:
    path = Path(output_dir)
    path.mkdir(parents=True, exist_ok=True)
    existing = [name for name in names if (path / name).exists()]
    if existing:
        raise FileExistsError(f"refusing to overwrite existing outputs: {', '.join(existing)}")
    return path


def write_csv(path: Path, fields: tuple[str, ...], rows: list[dict]) -> None:
    with path.open("x", newline="", encoding="utf-8") as csv_file:
        writer = csv.DictWriter(csv_file, fieldnames=fields)
        writer.writeheader()
        writer.writerows(rows)


def write_json(path: Path, data: dict) -> None:
    with path.open("x", encoding="utf-8") as json_file:
        json.dump(data, json_file, indent=2, sort_keys=True)
        json_file.write("\n")


def public_key_fingerprints(keypairs: dict[str, tuple[object, object]]) -> dict[str, str]:
    fingerprints = {}
    for scheme, (_, public_key) in keypairs.items():
        from cryptography.hazmat.primitives import serialization

        if scheme.startswith("RSA-"):
            encoded = public_key.public_bytes(
                serialization.Encoding.DER,
                serialization.PublicFormat.SubjectPublicKeyInfo,
            )
        elif scheme.startswith("ECDH-"):
            encoded = public_key.public_bytes(
                serialization.Encoding.X962,
                serialization.PublicFormat.UncompressedPoint,
            )
        else:
            encoded = public_key.public_bytes(
                serialization.Encoding.Raw,
                serialization.PublicFormat.Raw,
            )
        fingerprints[scheme] = hashlib.sha256(encoded).hexdigest()
    return fingerprints


def seed_metadata(seed: int, seed_source: str) -> dict:
    return {
        "random_seed": seed,
        "random_seed_source": seed_source,
        "randomization": "Python random.Random pseudo-random ordering; the experiment-specific assignment schedule is recorded separately",
        "randomization_note": (
            "The root seed is drawn from OS entropy unless explicitly supplied. "
            "Design-based inference treats the seeded PRNG shuffle as a uniform random assignment; "
            "this is an idealization of the finite-state PRNG."
        ),
    }
