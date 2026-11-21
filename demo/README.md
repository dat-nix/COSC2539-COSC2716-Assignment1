# COSC2539 Demonstration and Presentation

This folder contains a short presentation interface that reuses the repository's real cryptographic functions. The demos are functional examples only: they do not measure execution time, run an experiment, write CSVs, or access the saved experimental results.

## Setup

Run from the repository root:

~~~sh
cd /home/datnix/Projects/University/asm1-security_in_computing
source .venv/bin/activate
python --version
python -c 'import cryptography; print("cryptography", cryptography.__version__)'
~~~

The available project environment reports Python 3.14.10 and cryptography 50.0.2, matching the report's recorded Symmetric/Hybrid environment. The system Python also reports Python 3.14.10 but has cryptography 49.0.0; use the activated .venv for recording. Pandoc 3.12.1 and LibreOffice 25.8.4.2 are available for slide generation and preview. The slide build uses Pandoc's PowerPoint writer and its installed reference template; it does not require python-pptx or add a project dependency.

## Run the demonstrations

Run these separately and in this order. Each command uses fresh in-memory keys/nonces where its construction requires them. No secret key, nonce, ciphertext, or full envelope is printed.

~~~sh
python -m demo.run_demo hashing
python -m demo.run_demo symmetric
python -m demo.run_demo hybrid
~~~

### Expected behavior

- **Hashing:** shows the original message and trusted SHA-256 digest; the modified message is rejected against that digest, while its attacker-recomputed unkeyed digest matches. The latter is not source authentication.
- **Symmetric:** a valid AES-256-GCM envelope returns the original message. A changed authentication tag is rejected, and the decryption function returns no plaintext.
- **Hybrid:** a generated recipient RSA key pair is used. RSA-OAEP-SHA256 wraps a fresh AES key and AES-GCM protects the payload. The valid envelope returns the original message; a changed tag fails at AES-GCM authentication with no plaintext in the outcome.

The cryptographic API uses random keys and nonces, so secret values and envelope bytes vary. The displayed behavior and status labels should remain the same. Actual successful wrapper output is preserved in fallback_outputs.txt for rehearsal or a clearly identified prerecorded fallback.

## Verification commands

Run the newly added presentation-wrapper checks and the existing focused functional suites:

~~~sh
python -m unittest discover -s tests -p 'test_demo.py' -v
python -m unittest discover -s tests -p 'test_hashing.py' -v
python -m unittest discover -s tests -p 'test_symmetric_crypto.py' -v
python -m unittest discover -s tests -p 'test_asymmetric_hybrid.py' -v
~~~

These commands run functional checks only. Do not run any experiment runner or benchmark as part of the presentation. The wrapper tests assert that changed inputs are rejected and no invalid-call plaintext is returned.

## Build the editable PowerPoint

The source slides are presentation.md; the reusable restrained color/font template is reference.pptx. The template is derived from the Pandoc default reference presentation and uses a white background, navy/teal accents, and Arial theme fonts. Slide text remains editable in PowerPoint; the two existing report charts are embedded as images.

The template was created once with:

~~~sh
python demo/build_presentation.py --create-template
~~~

To build a new output without replacing an existing file:

~~~sh
python demo/build_presentation.py --output /tmp/cosc2539-presentation-preview.pptx
~~~

When preserving the previous output and intentionally replacing the default deck:

~~~sh
cp demo/presentation.pptx demo/presentation.previous.pptx
python demo/build_presentation.py --overwrite
~~~

The command runs Pandoc from the project root so the relative chart paths resolve. It checks for both source figures, nine slides, embedded media, and speaker notes. Speaker notes include each slide's approximate duration, talking points, and transition.

To render a PDF preview in a separate directory:

~~~sh
mkdir -p /tmp/cosc2539-presentation-pdf
libreoffice-bin --headless --convert-to pdf --outdir /tmp/cosc2539-presentation-pdf demo/presentation.pptx
~~~

## Recording checklist

- [ ] Use the activated .venv and run the three demos once before recording.
- [ ] Arrange recording so both the presenter's face and the shared screen remain visible throughout.
- [ ] Enlarge terminal text; close unrelated windows and notifications.
- [ ] Keep the commands in separate terminal calls; do not run experiment or analysis commands.
- [ ] Pre-open a terminal in the repository root and keep each demo command ready to paste.
- [ ] Keep the pointer on the relevant success/rejection lines and avoid displaying key material.
- [ ] If a live command fails, identify the fallback_outputs.txt capture as a prerecorded demonstration; do not imply it ran live.
- [ ] Rehearse the 5:45 script and use a timer; keep the final video between 5 and 6 minutes.
- [ ] Review the full recording for readable terminal text, visible face/screen, privacy, and duration before submission.

## Scope reminders

The report and presentation describe the Nozomi Networks role as hypothetical academic context; this code does not connect to company, industrial, or supermarket systems. The demos show tested function, not a formal proof. Shared-key authentication does not establish an individual sender's identity. The hybrid example does not add sender authentication or replay protection. The local RQ3 timing measurements do not establish a remotely exploitable timing side channel.

The title slide attributes authorship to COSC2539 Assignment 1. Its subtitle explicitly marks the Cybersecurity Research Engineer role as academic role-play; it does not imply employment or company endorsement. AES-GCM in the project also authenticates its configured associated-data context. The RSA hybrid envelope does not provide sender authentication, replay protection, or forward secrecy if its static recipient private key is later compromised.
