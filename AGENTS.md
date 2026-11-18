# AGENTS.md

## Project: Cryptography Under Adversarial Conditions

### 1. Project objective

Develop a Python-based experimental framework for an academic cryptography research project.

Main research question:

"How do selected cryptographic algorithms differ in their performance and ability to detect data tampering and invalid ciphertext under controlled adversarial conditions?"

The project must support:

- Cryptographic performance benchmarking.
- Controlled adversarial testing.
- Integrity verification and tampering detection.
- Statistical analysis of experimental results.

### 2. Research scope

Implement the following nine algorithms/schemes.

**Hashing**

1. SHA-256
2. SHA3-256
3. BLAKE2b-256 (digest_size=32)

**Symmetric encryption**

1. AES-256-GCM
2. ChaCha20-Poly1305
3. AES-256-CBC + HMAC-SHA256 (Encrypt-then-MAC)

**Asymmetric-based hybrid encryption**

1. RSA-OAEP + AES-256-GCM
2. ECDH P-256 + HKDF + AES-256-GCM
3. X25519 + HKDF + AES-256-GCM

Important:

- ECDH and X25519 are key-agreement mechanisms, not standalone public-key encryption algorithms.
- Describe the third category as asymmetric-based hybrid encryption schemes.
- RSA must encrypt/wrap the symmetric AES key, not the entire input file.
- Use authenticated encryption for hybrid payloads.
- Generate keys and manage nonces/IVs correctly.
- Never reuse an AES-GCM nonce with the same key in normal encryption experiments.
- CBC must verify HMAC before decryption.

### 3. Experimental configuration

Input sizes:

- 1 KB
- 10 KB
- 100 KB
- 1 MB
- 10 MB

Benchmark configuration:

- 5 warm-up runs.
- 30 measured repetitions per configuration.
- Use time.perf_counter() for timing.
- Preserve raw observations in CSV.
- Record system and software environment metadata.
- Do not fabricate or modify experimental results.

### 4. Research questions

RQ1: How does input data size affect execution time?

RQ2: How do selected cryptographic schemes detect modified data and respond to invalid ciphertext or authentication data?

RQ3: What processing-time differences occur between valid and invalid inputs?

### 5. Adversarial test scenarios

Hashing:

- Hash original input and retain its trusted digest.
- Modify input and calculate a new digest.
- Compare against the trusted digest.
- Explain that an untrusted digest supplied alongside modified data does not provide authentication.

Encryption:

- Valid ciphertext and authentication data.
- Modified ciphertext.
- Invalid authentication tag or MAC.
- Record whether input is accepted or rejected.

For CBC + HMAC:

- Use Encrypt-then-MAC.
- Verify MAC before decrypting.
- Never expose unauthenticated plaintext.

### 6. Statistical analysis

- Use One-way ANOVA as the minimum statistical analysis for RQ1.
- Analyze each algorithm and relevant operation separately.
- Do not combine fundamentally different cryptographic operations into one ANOVA.
- Check statistical assumptions.
- Use appropriate post-hoc analysis when needed.
- RQ2 primarily uses detection and rejection rates.
- RQ3 compares valid and invalid processing times.
- Never invent statistical significance or experimental findings.

### 7. Engineering requirements

- Modular and maintainable Python code.
- Separate cryptographic implementations, attack simulation, benchmarking, and analysis.
- Include automated tests.
- Use explicit error handling.
- Keep cryptographic parameters configurable.
- Document important security decisions.
- Provide reproducible experiment commands.
- Keep dependencies minimal.
- Do not build a GUI or web application.

### 8. Development rules

- Implement incrementally.
- Do not implement the entire project in one unreviewed change.
- Before modifying files, inspect the existing project.
- Preserve working code unless a change is necessary.
- Run relevant tests after implementation.
- Report changed files, commands executed, and test results.
- Never claim a task is complete without verification.
- Do not generate fabricated benchmark data.
- Do not add unrelated features or expand research scope without approval.

### 9. Academic integrity

This is an academic research project. The implementation must be understandable, reproducible, and honestly documented.

Do not fabricate measurements, citations, or research findings.

Clearly distinguish measured results from expected behavior and theoretical explanations.
