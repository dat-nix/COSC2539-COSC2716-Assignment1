---
title: "An Experimental Evaluation of Cryptographic Mechanisms Relevant to Secure IoT Communications Under Adversarial Conditions"
subtitle: "Academic role-play: Cybersecurity Research Engineer scenario"
author: "COSC2539 Assignment 1"
lang: en
---

::: notes
0:00–0:25. The slide identifies COSC2539 Assignment 1 as the academic author and labels the Nozomi Networks Labs role as a hypothetical academic scenario, not employment or company sponsorship. State the bounded IoT/IIoT relevance and that this was not a test of deployed devices. Transition: outline the three research questions.
:::

# Study design

- **Hashing:** SHA-256 | SHA3-256 | BLAKE2b-256.
- **Symmetric:** AES-256-GCM | ChaCha20-Poly1305 | AES-256-CBC + HMAC-SHA256.
- **Hybrid:** RSA-OAEP | P-256 ECDH + HKDF | X25519 + HKDF; each uses AES-256-GCM for payloads.
- **Payloads:** 1 KiB–10 MiB. RQ1 used 30 blocks per category; five warm-ups were excluded.
- RQ1 studies size; RQ2 tests function; RQ3 compares complete valid/invalid paths.

::: notes
0:25–0:50. State the three groups, five sizes, and 30 RQ1 blocks. Conditions were shuffled within blocks, then measured sequentially on one laptop; timing scopes differ by category. Transition: begin with the digest check.
:::

# Demo 1 | SHA-256 integrity check

- Original message and retained trusted digest
- Modified message compared with the trusted digest: **REJECTED**
- The same modified message with a recomputed unkeyed digest: **MATCHES**
- A digest match establishes consistency with the supplied digest, not its source.

Run: **python -m demo.run_demo hashing**

::: notes
0:50–1:35. Run the hashing command. Point to the trusted digest, the rejected modified message, then the match with the recomputed digest. Explain that an unkeyed hash detects a change only relative to a trusted reference; an attacker replacing both message and digest can recompute the digest. The full RQ2 matrix has 30 configurations, separate from RQ3 timing rows. Transition: move from change detection to authenticated encryption.
:::

# Demo 2 | AES-256-GCM

- Encrypt a short payload with a fresh key and nonce
- Valid envelope: decryption succeeds and returns the original payload
- Altered tag: **REJECTED**; failed call returns no plaintext.
- AEAD protects confidentiality and authenticates ciphertext plus configured associated data.
- A shared-key tag does not independently identify a sender.

Run: **python -m demo.run_demo symmetric**

::: notes
1:35–2:20. Run the AES-GCM command. Show that the valid message returns, then show rejection after one tag byte is altered and that no plaintext is returned. AES-GCM is an AEAD construction; this implementation authenticates ciphertext and its configured associated-data context while providing confidentiality. A shared key does not identify an individual sender. Transition: explain how public-key operations protect or derive a payload key.
:::

# Demo 3 | RSA-OAEP + AES-256-GCM

- Recipient RSA key pair generated in memory
- RSA-OAEP-SHA256 wraps a fresh AES key
- AES-256-GCM encrypts and authenticates the payload
- Valid envelope: accepted
- Altered GCM tag: rejected at **AES-GCM authentication**, with no plaintext release
- No sender authentication or replay protection; no forward secrecy after later recipient-key compromise.

Run: **python -m demo.run_demo hybrid**

::: notes
2:20–3:05. Run the RSA hybrid command. Point out that RSA-OAEP wraps the fresh AES key, while GCM protects the payload. Contrast this with P-256 ECDH and X25519, which establish a shared secret that HKDF derives into the AES key. The valid envelope returns the original message; a changed tag fails at GCM authentication and the outcome contains no plaintext. This RSA envelope adds no sender authentication or replay protection and provides no forward secrecy against later compromise of its static recipient private key. Do not show private or session keys. Transition: turn to the measured results.
:::

# RQ1 | Payload size and measured time

![Displayed chart: Symmetric category only. All 15 within-series RQ1 tests were Holm-significant; no between-scheme significance tests were conducted.](results/symmetric/rq1/analysis/run_20261119_02/symmetric_rq1_execution_time.png)

::: notes
3:05–4:05. Show the existing Symmetric RQ1 chart and identify it as a Symmetric-category example. Explain the rising profiles as payload size increases. At 10 MiB, descriptive mean encryption times (ms) were 4.83, 16.37, and 9.54 for SHA-256, SHA3-256, and BLAKE2b-256; 2.76, 5.40, and 14.01 for AES-GCM, ChaCha20-Poly1305, and CBC-HMAC; and 3.45, 3.48, and 3.40 for RSA, ECDH, and X25519 Hybrid. These are descriptive comparisons across category-specific workflows, not statistical rankings. All 15 repeated-measures ANOVA input-size tests remained Holm-significant. Partial η² describes the input-size effect within each series, not between-scheme superiority. Mauchly rejected sphericity; residual-normality departures and possible temporal dependence qualify inference. No between-scheme significance tests were conducted. Transition: describe the functional outcomes.
:::

# RQ2 | What the tested inputs showed

| Category | Functional outcome |
|:--|:--|
| Hashing | 15/15 changes rejected against the trusted digest; 15/15 checks matched an attacker-recomputed unkeyed digest. |
| Symmetric | 15/15 valid accepted; 75/75 invalid rejected without plaintext. |
| Hybrid | 15/15 valid accepted; 70/70 invalid rejected without plaintext. |
::: notes
4:05–4:35. Summarize the RQ2 counts without listing every invalid-input class. Hashing shows why the digest must be trusted; symmetric and hybrid calls rejected the tested invalid cases without returning plaintext. These outcomes are specific to the tested inputs and implementations. Transition: the last question compares complete valid and failure paths.
:::

# RQ3 | Symmetric complete-path example

![Corrected run_20261119_02: Symmetric RQ3 mean decryption time by failure scenario and payload size.](results/symmetric/rq3/analysis/run_20261119_03/symmetric_rq3_execution_time.png)

::: notes
4:35–5:15. Show the corrected Symmetric RQ3 chart and read the Holm-significant counts: Hashing 0/45, Symmetric 36/75, Hybrid 17/60. The CBC-HMAC 10 MiB example was faster because this specified path rejected at MAC verification before CBC decryption: 5.592 ms compared with 9.463 ms valid, a mean paired change of −3.871 ms (adjusted p = .0075). This is a complete-path difference, not isolated authentication overhead. Faster rejection is not stronger security. These comparisons are conditional/exploratory, are affected by temporal dependence, and do not demonstrate a remote timing side channel. Non-significance is not equivalence. Transition: give the bounded conclusion.
:::

# Conclusion | Findings and scope

- **RQ1:** larger payloads generally took longer in the tested series.
- **RQ2:** trusted digests detect changes; tested encryption schemes reject invalid inputs.
- **RQ3:** timing varied by complete path and failure stage.
- **Contribution:** evidence for planning device- and protocol-specific tests.
- **Scope:** one Gentoo laptop; no deployed-device, network, energy, or remote-side-channel testing.

::: notes
5:15–5:45. Close by connecting the three questions: RQ1 is performance, RQ2 is functional tampering behavior, and RQ3 is the timing of complete valid and invalid paths. This study offers bounded implementation evidence for planning later IoT/IIoT device and protocol tests; it is not a deployment assessment or a complete security solution. Thank the audience.
:::
