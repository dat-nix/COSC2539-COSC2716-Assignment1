# Presentation plan (5 minutes 30 seconds)

**Format:** record the student and desktop together (webcam overlay plus screen capture) for the entire presentation. Keep the terminal font large enough to read. Show actual function behavior first, then one result plot/table per category. This is a plan, not a completed video or script.

| Time | What appears on screen | What the student demonstrates / says | Security function | Result to highlight |
|---|---|---|---|---|
| 0:00-0:35 | Title slide with the three RQs and a small pipeline: hash / symmetric / hybrid | State the question: how size and tampering behavior vary across constructions. Clarify that the timing scopes differ, so this is not one speed leaderboard. | Study framing | 30 blocks and five binary payload sizes, with one host and assumption caveats. |
| 0:35-1:30 | Python REPL using hashing.digests; show the trusted and recomputed digest comparisons | Call sha256(b"hello"); compare modified b"jello" with the trusted digest, then with its recomputed digest. Explain why a public unkeyed digest cannot authenticate its source. | Change detection relative to a trusted reference; no source authentication | RQ2: all 30 documented functional configurations are present (15 trusted-reference rejections; 15 comparisons against attacker-recomputed digests passed). RQ3 has 0/45 significant differences; this does not imply equivalent times. |
| 1:30-2:30 | Python loop over `symmetric.schemes.SCHEMES`; show CBC-HMAC check order from its test | Round-trip a short message with AES-GCM, ChaCha20-Poly1305, and CBC-HMAC; modify an AEAD tag or CBC MAC and show rejection without plaintext. | AEAD authentication; CBC-HMAC Encrypt-then-MAC before decryption | Symmetric RQ2: 75/75 invalid functional cases rejected with no plaintext. Corrected RQ3: 36/75 adjusted comparisons, conditional/exploratory. |
| 2:30-3:35 | Python loop over the three `asymmetric.schemes.SCHEMES`; show only outcomes, never key material | Encrypt to each generated recipient key, recover the payload, then modify each GCM tag and show rejection/no plaintext. Explain RSA key wrapping and ECDH/X25519 key agreement plus HKDF. | Hybrid key protection/agreement plus AES-GCM payload authentication | Asymmetric RQ2: 70/70 invalid cases rejected with no plaintext. RQ3: 17/60 adjusted comparisons, exploratory due temporal dependence. |
| 3:35-5:00 | Show the report's RQ1 endpoint table, the two existing RQ1 plots (Symmetric and hybrid), then the RQ3 comparison table | Compare trends within each category: digest processing; AEAD vs CBC-HMAC; key processing plus AES-GCM. Point out that all 10 MiB means exceed their 1 KiB means. Explain failed ANOVA assumptions and why cross-category times cannot be ranked. | Comparative interpretation of performance and integrity behavior | RQ1 omnibus tests significant within each category after Holm correction; GG corrected sphericity, but residual normality failed. RQ3 significant counts differ by failure stage, not a universal invalid-input effect. |
| 5:00-5:30 | Conclusion slide with three short takeaways and two limitations | Summarize trusted digest, authenticated decryption, and failure-stage timing. State no formal security proof, no equivalence claim, one host, and no claim of remote exploitability. | Honest security reporting | Ask the audience to interpret findings only within the tested code/environment. |

## Live demonstration snippets

Use these as short terminal/REPL demonstrations. They call the actual project APIs and do not run benchmarks. The student should test the snippets before recording and avoid showing secret key values.

### Hashing

~~~python
from hmac import compare_digest
from hashing.digests import sha256

original = b"hello"
trusted = sha256(original)
modified = b"Hello"
print(compare_digest(sha256(modified), trusted))  # False

attacker_digest = sha256(modified)
print(compare_digest(sha256(modified), attacker_digest))  # True
~~~

### Symmetric

~~~python
from dataclasses import replace
from symmetric.aes_gcm import generate_key, encrypt, decrypt
from symmetric.common import InvalidCiphertextError

key = generate_key()
envelope = encrypt(b"demo payload", key)
print(decrypt(envelope, key))

bad_tag = bytes([envelope.tag[0] ^ 1]) + envelope.tag[1:]
try:
    decrypt(replace(envelope, tag=bad_tag), key)
except InvalidCiphertextError:
    print("tampering rejected; no plaintext returned")
~~~

### Asymmetric-based hybrid

~~~python
from dataclasses import replace
from asymmetric.common import RSA_SCHEME
from asymmetric.schemes import SCHEME_BY_NAME, generate_recipient_keypairs

private_key, public_key = generate_recipient_keypairs()[RSA_SCHEME]
scheme = SCHEME_BY_NAME[RSA_SCHEME]
envelope = scheme.encrypt(b"demo payload", public_key)
print(scheme.attempt_decrypt(envelope, private_key).accepted)

bad_tag = bytes([envelope.tag[0] ^ 1]) + envelope.tag[1:]
outcome = scheme.attempt_decrypt(replace(envelope, tag=bad_tag), private_key)
print(outcome.accepted, outcome.plaintext_released, outcome.failure_stage)
~~~

The full recording must remain between 5:00 and 6:00, show both face and screen, and be uploaded to YouTube or Canvas as directed by the course site. Do not show private keys or claim that the demo proves security against all attacks.

