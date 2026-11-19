"""Shared envelope and safe failure types for the symmetric schemes."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class CiphertextEnvelope:
    """In-memory message fields; secret keys are deliberately not part of it."""

    scheme: str
    ciphertext: bytes | None
    nonce: bytes | None = None
    tag: bytes | None = None
    iv: bytes | None = None
    mac: bytes | None = None


class InvalidCiphertextError(ValueError):
    """Uniform public error for malformed or unauthentic messages.

    ``_failure_stage`` is private diagnostic data for the local experiment
    runner. Applications should expose only the identical public message.
    """

    def __init__(self, failure_stage: str):
        super().__init__("invalid ciphertext or authentication data")
        self._failure_stage = failure_stage


def require_bytes(value: object, field: str) -> bytes:
    if not isinstance(value, bytes):
        raise InvalidCiphertextError("envelope_validation")
    return value
