# COSC2539 Presentation Script

**Target:** 5 minutes 45 seconds, including terminal demonstrations and transitions. Keep the face and screen visible together for the whole recording.

**Fallback rule:** Use `fallback_outputs.txt` only if a live command fails, and identify that display as prerecorded. Do not describe prerecorded output as a live run.

## 0:00–0:25 | Introduction

**Say:** Framed as a hypothetical Cybersecurity Research Engineer task inspired by Nozomi Networks Labs, this study asks how selected mechanisms behave as payloads grow and data is modified. It was not company-commissioned and ran on one Gentoo laptop, not deployed devices. RQ1 studies size, RQ2 tampering, and RQ3 complete-path timing.

**Show/do:** [SLIDE 1] Keep the webcam overlay visible beside the slide. The author field identifies the assignment; the subtitle labels the Nozomi-related role as academic role-play.

**Transition:** “First, here is the measurement design.”

## 0:25–0:50 | Experimental design

**Say:** Nine constructions span hashing, symmetric encryption, and asymmetric-based hybrid encryption, across five sizes from one kibibyte to ten mebibytes. RQ1 used thirty blocks per category and excluded five warm-ups. Conditions were shuffled within each block, then measured sequentially on one Gentoo laptop. The three questions use different workflows.

**Show/do:** [SLIDE 2] Point to the three groups, nine constructions, five sizes, and RQ1 block design.

**Transition:** “The first security function is checking a message against a trusted digest.”

## 0:50–1:35 | Demo 1: Hashing

**Say:** The original SHA-256 digest is retained as trusted. Comparing the modified message with it rejects the change. Recomputing an unkeyed digest for that modified message makes the comparison match. This is not a SHA-256 weakness; it shows that the digest source must be trusted. The RQ2 matrix contains thirty configurations across three hashes, five sizes, and two scenarios.

**Show/do:** [RUN: `python -m demo.run_demo hashing`] Point to the original message and trusted digest, then “REJECTED” and the attacker-recomputed “MATCHES” result. [PAUSE: leave both outcomes visible.]

~~~sh
python -m demo.run_demo hashing
~~~

**Expected:** A digest is shown; the modified input is rejected against the trusted digest and matches the attacker-recomputed digest.

**Transition:** “Encryption needs confidentiality, and authenticated encryption also checks integrity.”

## 1:35–2:20 | Demo 2: AES-256-GCM

**Say:** A fresh in-memory key and nonce encrypt a short message. AES-GCM is an AEAD construction: this implementation authenticates the ciphertext and its configured associated-data context. The valid envelope returns the original plaintext. I change one tag byte; decryption rejects it and returns no plaintext. Shared-key authentication does not identify an individual sender.

**Show/do:** [RUN: `python -m demo.run_demo symmetric`] Point to the valid plaintext match, tag rejection, and `Plaintext returned ... False`. [PAUSE: leave the rejection and no-plaintext status visible.]

~~~sh
python -m demo.run_demo symmetric
~~~

**Expected:** Valid envelope accepted; tampered tag rejected; no plaintext returned after failure.

**Transition:** “Hybrid encryption uses public-key methods for a symmetric key, then symmetric encryption for the data.”

## 2:20–3:05 | Demo 3: RSA-OAEP hybrid

**Say:** RSA-OAEP wraps only a fresh AES key; AES-GCM encrypts and authenticates the payload. Recipient keys stay in memory and are never printed. P-256 ECDH and X25519 establish shared secrets; HKDF derives AES keys. The valid envelope succeeds; a changed tag fails GCM authentication without plaintext. RSA does not authenticate senders or prevent replay, and provides no forward secrecy against later compromise of the static recipient private key.

**Show/do:** [RUN: `python -m demo.run_demo hybrid`] Point to the OAEP key-wrapping explanation, successful valid result, GCM failure stage, and `Plaintext released ... False`. [PAUSE: leave the rejection visible.]

~~~sh
python -m demo.run_demo hybrid
~~~

**Expected:** Valid envelope accepted; tampered tag rejected at AES-GCM authentication; plaintext released is false.

**Transition:** “The demonstrations show function; the experiments measured performance and outcomes across blocks.”

## 3:05–4:05 | RQ1: Size and execution time

**Say:** This is a Symmetric-category example: its encryption and decryption means rise with payload size. At ten mebibytes, mean encryption times in milliseconds were Hashing: 4.83, 16.37, 9.54; Symmetric: 2.76, 5.40, 14.01; Hybrid: 3.45, 3.48, 3.40. These category-specific workflows are descriptive, not a statistical speed ranking. All fifteen within-series repeated-measures ANOVA size tests remained Holm-significant. Partial eta-squared describes the size effect within each series. Mauchly rejected sphericity; residual and dependence diagnostics limit inference. No between-scheme tests were conducted.

**Show/do:** [SLIDE 6] The caption identifies the chart as Symmetric only. Point to its encryption and decryption profiles; describe the other category means verbally as descriptive comparisons only.

**Transition:** “RQ2 asks what happened when the tested data or envelopes were invalid.”

## 4:05–4:35 | RQ2: Functional outcomes

**Say:** All valid Symmetric and Hybrid cases were accepted; their 75 and 70 invalid cases were rejected without plaintext. Hashing rejected all fifteen changes against trusted digests, while all fifteen attacker-recomputed checks matched. These finite tests are not a security proof: message integrity does not identify a sender or provide replay protection.

**Show/do:** [SLIDE 7] Point to the Hashing, Symmetric, and Hybrid outcome rows. Emphasize that they are tested cases, not proofs.

**Transition:** “The last question times complete valid and invalid paths.”

## 4:35–5:15 | RQ3: Complete paths (Symmetric example)

**Say:** After Holm correction, significant contrasts were Hashing zero of forty-five, Symmetric thirty-six of seventy-five, and Hybrid seventeen of sixty. At ten mebibytes, CBC-HMAC ciphertext tampering averaged 5.592 milliseconds versus 9.463 valid, a paired difference of minus 3.871 milliseconds, adjusted p-value .0075. These exploratory differences cover complete paths, not isolated authentication overhead. Faster rejection is not stronger security, and local timings do not establish a remote side channel.

**Show/do:** [SLIDE 8] Show the corrected-run Symmetric RQ3 chart and the Holm-adjusted comparison counts. Keep the 10 MiB CBC-HMAC example visible while explaining its complete-path boundary.

**Transition:** “Together, the three questions provide a bounded implementation-level view.”

## 5:15–5:45 | Conclusion and limitations

**Say:** RQ1 measured size-related performance, RQ2 tested functional tampering behavior, and RQ3 compared complete processing-path times. Together they offer bounded evidence for planning later IoT device and protocol tests, not a deployment ranking or complete security solution. This study used one laptop and did not measure energy, network behavior, or remote attacks. Thank you.

**Show/do:** [SLIDE 9] Finish looking at the camera with the single-host limitation visible. [END: stop recording after the final sentence.]

## Timing and recording

The schedule totals 5:45. The spoken narration is approximately 520 words: about 4:21 at 120 words per minute or 4:01 at 130 words per minute. The remaining 1:24–1:44 covers three brief terminal runs, showing outputs, slide transitions, and pauses. Pre-open the terminal in the repository root and keep the commands ready to paste. Speak clearly, do not read code, and rehearse with a timer. Keep face and screen visible for the full recording.
