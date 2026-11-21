---
title: "An Experimental Evaluation of Cryptographic Mechanisms Relevant to Secure IoT Communications Under Adversarial Conditions"
subtitle: "COSC2539 Assignment 1 | Controlled Python implementation study"
author: "Hypothetical Cybersecurity Research Engineer | Nozomi Networks Labs"
lang: en
---

::: notes
0:00–0:25. Introduce the hypothetical Nozomi Networks Labs research-engineer framing, clarifying that the study is not company-commissioned. State the bounded IoT/IIoT relevance and that it is not a test of deployed devices. Transition: outline the three research questions.
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
- Altered authentication tag: **REJECTED**
- Failed call returns no plaintext in this tested implementation.
- Shared-key authentication does not independently identify a sender.

Run: **python -m demo.run_demo symmetric**

::: notes
1:35–2:20. Run the AES-GCM command. Show that the valid message returns, then show rejection after one tag byte is altered and that no plaintext is returned. GCM provides authenticated encryption under its key and nonce assumptions; the shared key does not identify an individual sender. Transition: explain how public-key operations protect or derive a payload key.
:::

# Demo 3 | RSA-OAEP + AES-256-GCM

- Recipient RSA key pair generated in memory
- RSA-OAEP-SHA256 wraps a fresh AES key
- AES-256-GCM encrypts and authenticates the payload
- Valid envelope: accepted
- Altered GCM tag: rejected at **AES-GCM authentication**, with no plaintext release

Run: **python -m demo.run_demo hybrid**

::: notes
2:20–3:05. Run the RSA hybrid command. Point out that RSA-OAEP wraps the fresh AES key, while GCM protects the payload. Contrast this with P-256 ECDH and X25519, which establish a shared secret that HKDF derives into the AES key. The valid envelope returns the original message; a changed tag fails at GCM authentication and the outcome contains no plaintext. Do not show private or session keys. Transition: turn to the measured results.
:::

# RQ1 | Payload size and measured time

![Within-series RQ1 summary: 15 of 15 Holm-adjusted omnibus tests significant; diagnostics limit inference.](results/symmetric/rq1/analysis/run_20261119_02/symmetric_rq1_execution_time.png)

::: notes
3:05–4:05. Show the existing Symmetric RQ1 chart. Explain the rising profiles as payload size increases. At 10 MiB, the descriptive Hashing means were 4.83 ms for SHA-256, 16.37 for SHA3-256, and 9.54 for BLAKE2b-256; Symmetric encryption means were 2.76 for AES-GCM, 5.40 for ChaCha20-Poly1305, and 14.01 for CBC-HMAC; Hybrid encryption means were 3.45 for RSA, 3.48 for ECDH, and 3.40 for X25519. These values compare different category-specific workflows and are not statistical cross-category rankings. The ANOVAs test size effects within each series, not between algorithms; after Mauchly rejected sphericity, Greenhouse–Geisser corrections were used. Residual-normality departures and possible temporal dependence qualify the inferential results. Hashing measures digest calls, symmetric timing covers the complete call, and Hybrid timing also includes per-message key processing. Transition: describe the functional outcomes.
:::

# RQ2 | What the tested inputs showed

| Category | Functional outcome |
|:--|:--|
| Hashing | 15/15 changes rejected against the trusted digest; 15/15 checks matched an attacker-recomputed unkeyed digest. |
| Symmetric | 75/75 invalid cases rejected; no plaintext returned. |
| Hybrid | 70/70 invalid cases rejected; no plaintext returned. |

- These are finite implementation tests, not proofs of security.
- AEAD/CBC-HMAC message integrity is distinct from sender identity; hybrid key handling alone does not add sender authentication or replay protection.

::: notes
4:05–4:35. Summarize the RQ2 counts without listing every invalid-input class. Hashing shows why the digest must be trusted; symmetric and hybrid calls rejected the tested invalid cases without returning plaintext. These outcomes are specific to the tested inputs and implementations. Transition: the last question compares complete valid and failure paths.
:::

# RQ3 | Complete valid and invalid paths

![RQ3 Holm-significant paired contrasts: Hashing 0 of 45; Symmetric 36 of 75; Hybrid 17 of 60.](results/symmetric/rq3/analysis/run_20261119_03/symmetric_rq3_execution_time.png)

::: notes
4:35–5:15. Show the corrected Symmetric RQ3 chart and read the Holm-significant counts: Hashing 0/45, Symmetric 36/75, Hybrid 17/60. The CBC-HMAC 10 MiB example was faster because this specified path rejected at MAC verification before CBC decryption: 5.592 ms compared with 9.463 ms valid, a mean paired change of −3.871 ms (adjusted p = .0075). This is a complete-path difference, not isolated authentication overhead. Faster rejection is not stronger security. These comparisons are conditional/exploratory, are affected by temporal dependence, and do not demonstrate a remote timing side channel. Non-significance is not equivalence. Transition: give the bounded conclusion.
:::

# Conclusion | Three dimensions, limited scope

- **RQ1:** larger payloads generally required more measured processing time within the tested series.
- **RQ2:** trust and authentication mechanisms determined whether the tested changes were detected or rejected.
- **RQ3:** timing differences depended on the complete failure path and its stage.
- **Contribution:** implementation-level evidence to inform later device- and protocol-specific testing.
- **Limit:** one Gentoo laptop; no deployed-device, network, energy, or remote-side-channel evaluation.

::: notes
5:15–5:45. Close by connecting the three questions: RQ1 is performance, RQ2 is functional tampering behavior, and RQ3 is the timing of complete valid and invalid paths. This study offers bounded implementation evidence for planning later IoT/IIoT device and protocol tests; it is not a deployment assessment or a complete security solution. Thank the audience.
:::
