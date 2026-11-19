# Presentation Commands

Run these commands from the project root. They call the actual module APIs and use in-memory demo messages. They do not run benchmarks, write CSVs, save keys, or modify experimental data.

There is no dedicated short demo CLI in the project. The experiment runners write result files, so the commands below use the same tested functions directly.

## Setup and environment check

```sh
cd /home/datnix/Projects/University/asm1-security_in_computing
python3 -c 'import cryptography; print("cryptography", cryptography.__version__)'
```

The demo code needs the `cryptography` package; the standard-library hashing demo needs no extra package. Project requirements pin `cryptography==50.0.2`. The shell used to verify these snippets reported `49.0.0`; the snippets ran successfully there. Activate the course/project environment before recording if you need to match the experiment environment exactly. Do not describe the demo interpreter version as the benchmark environment.

## 1. Hashing: trusted digest and attacker-recomputed digest

```sh
python3 - <<'PY'
from hmac import compare_digest
from hashing.digests import sha256

original = b"hello"
trusted_digest = sha256(original)
modified = b"jello"
attacker_digest = sha256(modified)

print("Original:", original.decode("utf-8"))
print("Trusted SHA-256:", trusted_digest.hex())
print("Modified:", modified.decode("utf-8"))
print("Attacker-recomputed SHA-256:", attacker_digest.hex())
print("Modified data vs trusted digest:", compare_digest(sha256(modified), trusted_digest))
print("Modified data vs recomputed digest:", compare_digest(sha256(modified), attacker_digest))
PY
```

**Verified output:**

```text
Original: hello
Trusted SHA-256: 2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824
Modified: jello
Attacker-recomputed SHA-256: 187c9bceeb919e1b3e6d20fa50ecabf7d9d50b5343e8f9a3d912abb13929102e
Modified data vs trusted digest: False
Modified data vs recomputed digest: True
```

**Say:** The original digest detects the changed message because it is retained as trusted. If an attacker can replace the message and unkeyed digest together, the comparison passes; it does not establish the source.

**File effect:** None.

## 2. Symmetric encryption: successful round trip and tampering

```sh
python3 - <<'PY'
from dataclasses import replace

from symmetric.common import InvalidCiphertextError
from symmetric.schemes import SCHEMES

plaintext = b"COSC2539 symmetric demo"
for scheme in SCHEMES:
    key = scheme.generate_key()
    envelope = scheme.encrypt(plaintext, key)
    recovered = scheme.decrypt(envelope, key)
    if "CBC" in scheme.name:
        changed_mac = bytes([envelope.mac[0] ^ 1]) + envelope.mac[1:]
        invalid = replace(envelope, mac=changed_mac)
    else:
        changed_tag = bytes([envelope.tag[0] ^ 1]) + envelope.tag[1:]
        invalid = replace(envelope, tag=changed_tag)
    plaintext_released = False
    try:
        scheme.decrypt(invalid, key)
        plaintext_released = True
    except InvalidCiphertextError:
        pass
    print(f"{scheme.name}: valid recovered={recovered == plaintext}; invalid rejected={not plaintext_released}; plaintext released={plaintext_released}")
PY
```

**Verified output:**

```text
AES-256-GCM: valid recovered=True; invalid rejected=True; plaintext released=False
ChaCha20-Poly1305: valid recovered=True; invalid rejected=True; plaintext released=False
AES-256-CBC+HMAC-SHA256: valid recovered=True; invalid rejected=True; plaintext released=False
```

**Optional source/test view for CBC's ordering:**

```sh
nl -ba symmetric/aes_cbc_hmac.py | sed -n '64,105p'
nl -ba tests/test_symmetric_crypto.py | sed -n '80,96p'
```

The implementation compares the HMAC before calling CBC decryption/unpadding; the test patches `_decrypt_cbc` and asserts it was not called for modified MAC/IV cases.

**Say:** GCM and ChaCha20-Poly1305 authenticate the envelope during decryption. CBC-HMAC uses Encrypt-then-MAC and rejects before decryption or unpadding.

**File effect:** None. Keys and envelopes exist only in process memory.

## 3. Asymmetric-based hybrid encryption: recipient, round trip, and tag tampering

```sh
python3 - <<'PY'
from dataclasses import replace

from asymmetric.schemes import SCHEMES, generate_recipient_keypairs

recipient_keys = generate_recipient_keypairs()
plaintext = b"COSC2539 hybrid demo"

for scheme in SCHEMES:
    private_key, public_key = recipient_keys[scheme.name]
    envelope = scheme.encrypt(plaintext, public_key)
    valid = scheme.attempt_decrypt(envelope, private_key)
    print(f"{scheme.name}: valid accepted={valid.accepted}; plaintext matches={valid.plaintext == plaintext}")

    changed_tag = bytes([envelope.tag[0] ^ 1]) + envelope.tag[1:]
    tampered = scheme.attempt_decrypt(replace(envelope, tag=changed_tag), private_key)
    print(f"  tampered accepted={tampered.accepted}; plaintext released={tampered.plaintext_released}; plaintext is None={tampered.plaintext is None}; failure={tampered.failure_stage}")
PY
```

**Expected output:** For RSA-OAEP, ECDH P-256, and X25519, the valid envelope reports `accepted=True` and `plaintext matches=True`. Each modified tag reports `accepted=False`, `plaintext released=False`, `plaintext is None=True`, and `failure=aes_gcm_authentication`.

**Say:** RSA-OAEP wraps a fresh AES session key. ECDH P-256 and X25519 establish a shared secret, and HKDF derives the AES key. AES-GCM protects the payload in all three schemes. No private key or session key is printed.

**File effect:** None. Recipient and ephemeral keys/envelopes remain in process memory.

## Results screen

Open `reports/final/cryptography_under_adversarial_conditions.pdf` and show the RQ1 endpoint table followed by the RQ2/RQ3 tables. Do not run an experiment or analysis command during the recording. The report distinguishes the 30 Hashing RQ2 functional checks from the 1,350 Hashing RQ3 timing observations.
