# COSC2539 Presentation Script

**Target:** 5 minutes 45 seconds, including terminal demonstrations and transitions. Keep the face and screen visible together for the whole recording.

## 0:00–0:25 | Introduction

**Say:** Framed as a hypothetical Cybersecurity Research Engineer task inspired by Nozomi Networks Labs, this study asks how selected mechanisms behave as payloads grow and data is modified. It was not company-commissioned and ran on one Gentoo laptop, not deployed devices. RQ1 studies size, RQ2 tampering, and RQ3 complete-path timing.

**Show/do:** Slide 1. Keep the webcam visible beside the slide.

**Transition:** “First, here is the measurement design.”

## 0:25–0:50 | Experimental design

**Say:** Nine constructions span hashing, symmetric encryption, and asymmetric-based hybrid encryption, across five sizes from one kibibyte to ten mebibytes. RQ1 used thirty blocks per category and excluded five warm-ups. Conditions were shuffled within each block, then measured sequentially on one Gentoo laptop. The three questions use different workflows.

**Show/do:** Slide 2. Point to the three groups and five sizes.

**Transition:** “The first security function is checking a message against a trusted digest.”

## 0:50–1:35 | Demo 1: Hashing

**Say:** The original SHA-256 digest is retained as trusted. Comparing the modified message with it rejects the change. Recomputing an unkeyed digest for that modified message makes the comparison match. This is not a SHA-256 weakness; it shows that the digest source must be trusted. The RQ2 matrix contains thirty configurations across three hashes, five sizes, and two scenarios.

**Show/do:** Run the hashing command. Point to the trusted digest, “REJECTED,” then “MATCHES.”

~~~sh
python -m demo.run_demo hashing
~~~

**Expected:** A digest is shown; the modified input is rejected against the trusted digest and matches the attacker-recomputed digest.

**Transition:** “Encryption needs confidentiality, and authenticated encryption also checks integrity.”

## 1:35–2:20 | Demo 2: AES-256-GCM

**Say:** A fresh in-memory key and nonce encrypt a short message. The valid AES-GCM envelope returns the original plaintext. I change one tag byte; decryption rejects it and returns no plaintext. GCM provides authenticated encryption under the shared-key model, but a valid tag does not identify the sender.

**Show/do:** Run the AES-GCM command. Point to the valid plaintext match, tag rejection, and false plaintext-returned status.

~~~sh
python -m demo.run_demo symmetric
~~~

**Expected:** Valid envelope accepted; tampered tag rejected; no plaintext returned after failure.

**Transition:** “Hybrid encryption uses public-key methods for a symmetric key, then symmetric encryption for the data.”

## 2:20–3:05 | Demo 3: RSA-OAEP hybrid

**Say:** RSA-OAEP wraps a fresh AES key; AES-GCM encrypts and authenticates the payload. The recipient key pair stays in memory and is never printed. P-256 ECDH and X25519 instead derive a shared secret, and HKDF derives the AES key. A changed tag fails at GCM authentication, with no plaintext. OAEP does not encrypt the payload itself.

**Show/do:** Run the RSA hybrid command. Point out the OAEP key-wrapping explanation and GCM failure stage.

~~~sh
python -m demo.run_demo hybrid
~~~

**Expected:** Valid envelope accepted; tampered tag rejected at AES-GCM authentication; plaintext released is false.

**Transition:** “The demonstrations show function; the experiments measured performance and outcomes across blocks.”

## 3:05–4:05 | RQ1: Size and execution time

**Say:** The plot shows Symmetric encryption and decryption means rising with payload size. At ten mebibytes, Hashing means were 4.83, 16.37, and 9.54 milliseconds for SHA-256, SHA3-256, and BLAKE2b. Symmetric encryption means were 2.76 for AES-GCM, 5.40 for ChaCha, and 14.01 for CBC-HMAC; Hybrid means were 3.45 for RSA, 3.48 for ECDH, and 3.40 for X25519. All fifteen within-series ANOVAs remained Holm-significant. Mauchly rejected sphericity, and residual/dependence diagnostics limit inference. No between-scheme significance tests were conducted.

**Show/do:** Slide 6 and the existing Symmetric RQ1 chart. Emphasize that the chart is one category example; use the listed means as descriptive comparisons only.

**Transition:** “RQ2 asks what happened when the tested data or envelopes were invalid.”

## 4:05–4:35 | RQ2: Functional outcomes

**Say:** Hashing rejected all fifteen modified inputs against trusted digests; all fifteen attacker-recomputed digest checks matched. Symmetric rejected 75 of 75 invalid cases, and Hybrid 70 of 70, with no plaintext returned. These are finite test outcomes, not a general proof. Message integrity does not establish sender identity or replay protection.

**Show/do:** Slide 7. Point to the three outcome rows.

**Transition:** “The last question times complete valid and invalid paths.”

## 4:35–5:15 | RQ3: Complete processing paths

**Say:** After Holm correction, significant contrasts were zero of forty-five for Hashing, thirty-six of seventy-five for Symmetric, and seventeen of sixty for Hybrid. At ten mebibytes, CBC-HMAC tampering averaged 5.592 milliseconds versus 9.463 valid, a mean paired change of minus 3.871 milliseconds, adjusted p-value .0075. Timing covers the complete path, not isolated authentication overhead. Faster rejection is not stronger security, and local timing does not establish a remote side channel.

**Show/do:** Slide 8 and the existing corrected-run RQ3 chart. Keep the adjusted-comparison counts visible.

**Transition:** “Together, the three questions provide a bounded implementation-level view.”

## 5:15–5:45 | Conclusion and limitations

**Say:** RQ1 measured size-related performance, RQ2 tested functional tampering behavior, and RQ3 compared complete processing-path times. Together they offer bounded evidence for planning later IoT device and protocol tests, not a deployment ranking or complete security solution. This study used one laptop and did not measure energy, network behavior, or remote attacks. Thank you.

**Show/do:** Slide 9. Finish looking at the camera, with the limitations line still visible.

## Timing and recording

The schedule totals 5:45. The spoken narration is about 517 words: approximately 4:19 at 120 words per minute or 3:59 at 130 words per minute. The remaining 1:26–1:46 is reserved for three brief terminal runs, pointing at outputs, and transitions. The live-demo segments allow about 15–22 seconds each. Speak clearly, do not read code, and rehearse with a timer. Keep face and screen visible for the full recording.
