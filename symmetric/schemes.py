"""Small registry used by the experiment runners."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Callable

from symmetric import aes_cbc_hmac, aes_gcm, chacha20_poly1305
from symmetric.common import CiphertextEnvelope


@dataclass(frozen=True)
class Scheme:
    name: str
    generate_key: Callable
    encrypt: Callable[[bytes, object], CiphertextEnvelope]
    decrypt: Callable[[CiphertextEnvelope, object], bytes]


SCHEMES = (
    Scheme(aes_gcm.NAME, aes_gcm.generate_key, aes_gcm.encrypt, aes_gcm.decrypt),
    Scheme(
        chacha20_poly1305.NAME,
        chacha20_poly1305.generate_key,
        chacha20_poly1305.encrypt,
        chacha20_poly1305.decrypt,
    ),
    Scheme(
        aes_cbc_hmac.NAME,
        aes_cbc_hmac.generate_key,
        aes_cbc_hmac.encrypt,
        aes_cbc_hmac.decrypt,
    ),
)
