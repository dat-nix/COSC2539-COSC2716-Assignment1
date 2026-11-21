# COSC2539 Demonstration and Presentation

The demo calls the repository's cryptographic implementations. These functional examples do not benchmark, run experiment suites, write CSVs, or require the local research-data directory. The presentation charts needed for viewing and building the deck are bundled in `demo/assets/`; their source paths and checksums are documented in [CHART_SOURCES.md](CHART_SOURCES.md).

## Setup

Run from the repository root in a virtual environment:

```sh
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements/asymmetric.txt -r requirements/symmetric.txt
```

The recorded project environment used CPython 3.14.10 and `cryptography` 50.0.2. The slide builder requires Pandoc. LibreOffice is optional and is only needed to make a PDF preview from the PowerPoint.

## Run the demonstrations

```sh
python -m demo.run_demo hashing
python -m demo.run_demo symmetric
python -m demo.run_demo hybrid
```

Each uses fresh in-memory keys/nonces as required and prints no key material.

- **Hashing:** a modified message fails comparison with the trusted SHA-256 digest; its attacker-recomputed unkeyed digest matches, illustrating that a plain digest does not authenticate its source.
- **Symmetric:** valid AES-256-GCM decryption succeeds; a changed authentication tag is rejected, with no plaintext returned.
- **Hybrid:** RSA-OAEP-SHA256 wraps a fresh AES key and AES-GCM protects the payload; a changed tag is rejected at GCM authentication, with no plaintext returned.

## Focused tests for a public clone

These tests cover the demo and core cryptographic behavior without the local research CSVs:

```sh
python -m unittest discover -s tests -p 'test_demo.py' -v
python -m unittest discover -s tests -p 'test_hashing.py' -v
python -m unittest discover -s tests -p 'test_symmetric_crypto.py' -v
python -m unittest discover -s tests -p 'test_asymmetric_hybrid.py' -v
```

The complete suite also includes checks against saved research datasets under `results/`. Those data files are intentionally excluded from public clones, so the dataset-dependent integration tests require the author's local research workspace.

## Build and view the presentation

The editable slide source is `demo/presentation.md`; the restrained Pandoc PowerPoint template is `demo/reference.pptx`. Both chart images are in `demo/assets/`, so the build does not read from `results/`.

To make a separate deck without overwriting the checked-in presentation:

```sh
python demo/build_presentation.py --output /tmp/cosc2539-presentation-preview.pptx
```

The builder runs Pandoc from the project root, checks the bundled images, nine slides, embedded media, and speaker notes. To render a PDF preview:

```sh
mkdir -p /tmp/cosc2539-presentation-pdf
libreoffice-bin --headless --convert-to pdf --outdir /tmp/cosc2539-presentation-pdf /tmp/cosc2539-presentation-preview.pptx
```

The existing editable deck and PDF preview can be opened directly as `demo/presentation.pptx` and `demo/presentation_preview.pdf`.

## Recording checklist

- [ ] Run the three demo commands once before recording.
- [ ] Show both the presenter's face and the shared screen throughout.
- [ ] Enlarge terminal text; close unrelated windows and notifications.
- [ ] Keep demo commands separate; do not run experiment or analysis commands during the demonstration.
- [ ] Keep the terminal at the repository root and each demo command ready to paste.
- [ ] Point to the success/rejection output without showing key material.
- [ ] If a live command fails, label any fallback capture as prerecorded.
- [ ] Rehearse the 5:45 script and use a timer; keep the recording between 5 and 6 minutes.
- [ ] Review the final recording for duration, readable screen text, and face/screen visibility.

The Nozomi Networks Labs role is hypothetical academic context. The demos do not connect to company, industrial, or supermarket systems. They demonstrate tested functions, not formal proofs. Shared-key authentication does not independently identify a sender; the hybrid example does not add sender authentication, replay protection, or forward secrecy against later compromise of its static recipient key.
