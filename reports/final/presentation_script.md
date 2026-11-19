# COSC2539 Assignment 1 Presentation Script

**Target duration:** about 5 minutes 30 seconds at a clear conversational pace, including the short terminal demonstrations. Keep the webcam overlay and project screen visible together throughout. Do not read the code aloud.

## 0:00–0:35 — Introduction

**Narration:**

Hello. This study asks how selected cryptographic algorithms differ in performance and tamper detection under controlled adversarial conditions. RQ1 concerns input size and execution time; RQ2 concerns responses to modified data and invalid ciphertext; RQ3 concerns the processing time of integrity checks and invalid-input rejection. I compare hashing, symmetric authenticated encryption, and asymmetric-based hybrid encryption. Because they perform different work, their times are not one universal speed ranking.

**Screen:** Title, the three RQs, and a simple flow: digest; shared-key encryption; public-key key handling plus symmetric payload encryption.

**Student action:** Face camera; point to each RQ. Keep the terminal ready in another window or pane.

**Expected output:** No command output in this segment.

**Key point:** The categories provide different security services and perform different work.

## 0:35–1:30 — Hashing integrity demonstration

**Narration:**

Hashing turns bytes into a fixed-length digest. I calculate SHA-256 for “hello” and retain it as the trusted reference. After changing the word to “jello,” comparison with that reference returns false: the change is detected. But a hash is public and unkeyed. If an attacker replaces both message and digest, the attacker recomputes a matching digest and the comparison returns true. That shows consistency, not source authentication. The saved Hashing RQ2 matrix contains 30 checks: three algorithms, five sizes, two scenarios, and one check per configuration.

**Screen:** Run Command 1 from `presentation_commands.md`; show the original and digest, then the two boolean comparisons.

**Student action:** Point to `False` for the modified message against the trusted digest, then `True` for the recomputed-digest comparison.

**Expected output:** The trusted SHA-256 is 64 hexadecimal characters; modified-versus-trusted is `False`; modified-versus-recomputed is `True`.

**Key point:** A hash can check consistency against a trusted reference. An unkeyed digest does not authenticate its source.

## 1:30–2:30 — Symmetric authenticated encryption

**Narration:**

These schemes use a shared secret key. I run AES-256-GCM, ChaCha20-Poly1305, and AES-CBC with HMAC-SHA256. All three recover the short message. I then change each AEAD tag or the CBC-HMAC value; every altered envelope is rejected, and no plaintext is returned. GCM and ChaCha authenticate during decryption. CBC-HMAC uses Encrypt-then-MAC: it checks a MAC over the IV and ciphertext before CBC decryption or padding removal. The functional experiment also rejected all 75 tested invalid symmetric cases without releasing plaintext.

**Screen:** Run Command 2. Then show the short test excerpt verifying CBC-HMAC does not call the decrypt routine when its MAC or IV is changed.

**Student action:** Point to each `valid recovered=True` and `plaintext released=False` line. Do not show key bytes.

**Expected output:** Three successful round trips, three rejections, and `plaintext released=False` for every tampered envelope.

**Key point:** The tested authenticated-encryption and Encrypt-then-MAC paths reject these modifications before returning plaintext.

## 2:30–3:35 — Asymmetric-based hybrid encryption

**Narration:**

The final demonstration sends a message to a generated recipient in all three hybrid schemes. RSA-OAEP wraps a fresh AES session key; it does not encrypt the payload. ECDH P-256 and X25519 instead establish a shared secret, and HKDF-SHA256 derives the AES key. AES-GCM encrypts and authenticates the payload in every scheme. Each valid message decrypts correctly. Changing its tag causes AES-GCM authentication failure, and the program returns no plaintext. Private keys remain in memory and are never printed.

**Screen:** Run Command 3. Show each scheme name, successful plaintext match, and tampered rejection with `plaintext released=False`.

**Student action:** Point out that the reported failure stage is AES-GCM authentication. Do not display any private-key or session-key material.

**Expected output:** Each scheme accepts its valid envelope; each tampered envelope is rejected at `aes_gcm_authentication` with no plaintext.

**Key point:** Public-key operations protect or derive a symmetric key; AES-GCM handles the payload and its integrity.

## 3:35–5:00 — Results and adversarial findings

**Narration:**

For RQ1, mean times rose from 1 KiB to 10 MiB within the measured series. At 10 MiB, hash means were 4.83, 16.37, and 9.54 milliseconds for SHA-256, SHA3-256, and BLAKE2b-256. Symmetric encryption means were 2.76 milliseconds for AES-GCM, 5.40 for ChaCha20-Poly1305, and 14.01 for CBC-HMAC. Hybrid encryption means were 3.45 milliseconds for RSA, 3.48 for ECDH, and 3.40 for X25519. These are descriptive values for different workflows, not a tested cross-category ranking. The repeated-measures ANOVAs remained significant after Holm correction; Greenhouse-Geisser addressed sphericity, but residual normality was rejected.

For RQ2, all 30 Hashing checks are complete: trusted-reference checks detected the modifications, while attacker-recomputed digest comparisons passed. Symmetric and hybrid tests also rejected every tested invalid message without plaintext. RQ3 had zero of 45 significant Hashing comparisons, 36 of 75 Symmetric comparisons, and 17 of 60 Hybrid comparisons after Holm correction. Dependence and assignment assumptions make these timing results exploratory or conditional. Non-significance does not prove equal times.

**Screen:** Show the report's RQ1 endpoint table, then the RQ2/RQ3 table. Keep the table large enough to read; do not scroll through raw CSV rows.

**Student action:** Emphasize that the timings compare complete operations within categories. Point to the assumption caveat and RQ3 counts, not just p-values.

**Expected output:** The report tables are visible. No new experiment or analysis is run.

**Key point:** Size affects measured processing time, functional tests demonstrate only the selected cases, and RQ3 timing differences depend on failure stage and design limitations.

## 5:00–5:30 — Limitations and conclusion

**Narration:**

This study used one machine and seeded pseudo-random payloads; system conditions also affect timing, and this is not a formal security proof. It establishes neither sender identity, replay protection, timing equivalence, nor a remote side channel. The key lesson: hashes need trusted references, authenticated encryption rejected tested changes, and hybrid schemes use public-key methods for keys and symmetric encryption for payloads. Thank you.

**Screen:** Three takeaway phrases and the limitations line; face remains visible.

**Student action:** Look at the camera for the closing sentence. End recording after the final frame.

**Expected output:** No command output.

**Key point:** Present measured findings within their tested scope; do not claim universal speed or security rankings.

## Timing check

The narration is approximately 530 words. At 120–130 words per minute it takes about 4:05–4:25, leaving roughly 65–85 seconds within the 5:30 schedule for command execution, pointing, pauses, and transitions. The conclusion is written for a brisk 30-second delivery. Rehearse with a timer and keep the complete recording between 5:00 and 6:00. Keep both face and screen visible throughout.
