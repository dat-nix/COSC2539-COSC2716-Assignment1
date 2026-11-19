# Presentation Demo Checklist

## Before recording

- [ ] Start in the project root: `/home/datnix/Projects/University/asm1-security_in_computing`.
- [ ] Use the project environment and check `python3 -c 'import cryptography; print(cryptography.__version__)'`.
- [ ] The project requirements pin cryptography 50.0.2. The shell used to verify the demo snippets had 49.0.0; both ran successfully there. If matching the experimental software environment is required, activate the environment that used 50.0.2.
- [ ] Confirm the three commands in `presentation_commands.md` are ready to paste. They were executed successfully from the project root and do not invoke experiment runners.
- [ ] Open `reports/final/cryptography_under_adversarial_conditions.pdf` at the RQ1 and RQ2/RQ3 results tables.
- [ ] Keep the webcam overlay and screen visible together for the entire 5:30 target recording. Increase terminal font size and close unrelated windows.
- [ ] Do not run `hashing.experiment_runner`, `symmetric.experiment_runner`, `symmetric.adversarial_runner`, `asymmetric.experiment_runner`, or `asymmetric.adversarial_runner` during the demo. These are experiment runners, not short presentation demos.
- [ ] Do not print or screenshot private keys, AES keys, session keys, nonces, or the full envelope. The commands print only outcomes, scheme names, and failure stages.

## Demo sequence

### Hashing

- [ ] Run Command 1 in `presentation_commands.md`.
- [ ] Show `hello` and its trusted digest, then `jello` and its attacker-recomputed digest; show `False` against the trusted digest and `True` against the recomputed one.
- [ ] Explain that the second comparison passes because ordinary hashes are unkeyed; it proves digest consistency, not who supplied the digest.
- [ ] State the corrected RQ2 design: 3 algorithms × 5 sizes × 2 tampering scenarios × 1 check = **30 complete configurations**.
- [ ] Keep the 1,350 RQ3 timing observations separate from these 30 RQ2 functional checks.

### Symmetric encryption

- [ ] Run Command 2 in `presentation_commands.md`.
- [ ] Confirm all three lines show `valid recovered=True`, `invalid rejected=True`, and `plaintext released=False`.
- [ ] Explain that AES-GCM and ChaCha20-Poly1305 authenticate during decryption. CBC-HMAC verifies its MAC over IV and ciphertext before CBC decryption or unpadding.
- [ ] If time permits, show the optional source/test view in the command reference; the test asserts CBC decryption is not called for invalid MAC/IV cases.
- [ ] Highlight the actual functional result: all 75 tested invalid symmetric cases were rejected without plaintext release.

### Asymmetric-based hybrid encryption

- [ ] Run Command 3 in `presentation_commands.md`.
- [ ] Confirm valid recipient envelopes match the original plaintext for RSA-OAEP, ECDH P-256, and X25519.
- [ ] Confirm every modified tag shows `accepted=False`, `plaintext released=False`, and `plaintext is None=True`.
- [ ] Explain RSA-OAEP key wrapping separately from ECDH/X25519 key agreement and HKDF; AES-GCM encrypts and authenticates each payload.
- [ ] Do not imply successful decryption authenticates a human sender; the evaluated envelopes have no sender signature.

### Results and close

- [ ] Show the report's RQ1 endpoint table and RQ2/RQ3 table; do not scroll raw CSV rows.
- [ ] State that all RQ1 within-series omnibus tests were significant after the specified Holm corrections, while residual normality was rejected and cross-category times were not statistically ranked.
- [ ] State the Holm-significant RQ3 counts accurately: Hashing 0/45, Symmetric 36/75, Hybrid 17/60. Explain that dependence limits timing inference and non-significance is not equivalence.
- [ ] Finish with one-machine, no-formal-proof, and no-side-channel-claim limitations.
- [ ] Stop at 5:00–5:55 and verify both face and screen remain visible.

## Expected-output fallback

The output excerpts in `presentation_commands.md` are the verified expected outputs. During rehearsal, capture a screenshot or short screen recording of each successful command into a local folder outside the repository. If a live command fails while recording, show the rehearsal capture as a pre-recorded demonstration and say so; do not present it as a successful live run.

Key checks to keep visible:

```text
Hashing: modified vs trusted = False; modified vs recomputed = True
Symmetric: valid recovered = True; invalid rejected = True; plaintext released = False
Hybrid: valid accepted = True; tampered accepted = False; plaintext released = False; plaintext is None = True
```

## After recording

- [ ] Stop screen capture and check the recorded duration and legibility.
- [ ] Confirm no private-key or session-key material is visible in the video.
- [ ] No project cleanup is required: the commands create no files; generated key objects are discarded when each Python process exits.
- [ ] Do not delete, move, or rewrite any existing experiment outputs.
