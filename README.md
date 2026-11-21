# COSC2539 / COSC2716 — Cryptography Under Adversarial Conditions

This repository contains Python implementations and a demonstration/presentation for an implementation-level study of selected cryptographic constructions under controlled payload-size and tampering conditions. It is not a benchmark of deployed IoT devices or a complete industrial security assessment.

## Research questions

- **RQ1:** How does input data size affect execution time?
- **RQ2:** How do selected cryptographic schemes detect modified data and respond to invalid ciphertext or authentication data?
- **RQ3:** What processing-time differences occur between valid and invalid inputs?

RQ1 analyzes each implementation and operation as a repeated-measures series. RQ2 records functional outcomes. RQ3 measures complete verification/decryption workflows for specified valid and invalid inputs. The results are implementation- and host-specific; RQ1 does not establish between-scheme significance, and local RQ3 timings do not establish a remote timing side channel.

## Constructions

| Group | Evaluated constructions |
|---|---|
| Hashing | SHA-256, SHA3-256, BLAKE2b-256 |
| Symmetric | AES-256-GCM, ChaCha20-Poly1305, AES-256-CBC with HMAC-SHA256 (Encrypt-then-MAC) |
| Asymmetric-based hybrid | RSA-OAEP with AES-GCM, ECDH P-256 with HKDF-SHA256 and AES-GCM, X25519 with HKDF-SHA256 and AES-GCM |

Hashing provides an unkeyed digest, not sender authentication. AEAD and CBC-HMAC provide integrity checks under their key assumptions; shared-key authentication does not independently identify an individual sender. The hybrid schemes use public-key operations for key wrapping or key agreement and symmetric authenticated encryption for the payload.

## Contributions and scope

The project's main contributions are the Python implementations, randomized-block experiment runners, analysis scripts, automated tests, matched descriptive RQ1 comparisons, RQ3 timing-magnitude analysis, and a demonstration wrapper that calls the project implementations. The research datasets and saved statistical outputs remain in the author's local workspace and are not included in the public repository.

The study used five payload sizes (1 KiB, 10 KiB, 100 KiB, 1 MiB, and 10 MiB), 30 measured blocks, and excluded five warm-ups; warm-up scheduling differs by category. It was conducted on one host and does not measure IoT-device energy, memory, network latency, or deployed protocol behavior. Some statistical assumptions and temporal-independence diagnostics require caution. Raw data, saved analyses, and the full report are intentionally local-only.

## Repository layout

```text
hashing/                         Hashing implementations, runners, and analysis
symmetric/                       Symmetric implementations, runners, and analysis
asymmetric/                      Asymmetric-based hybrid implementations and analysis
analysis/                         Cross-category RQ1/RQ3 comparative analysis
tests/                            Automated functional and analysis tests
requirements/                     Pinned dependency sets
demo/                             Demo wrapper, slide source, charts, deck, and script
demo/assets/                      Two chart images required by the presentation
```

`reports/`, `results/`, and `AGENTS.md` are ignored and kept in the author's local workspace. A public clone includes only the two presentation chart images in `demo/assets/`; those are exact copies of existing generated figures, not raw datasets. Their original CSV paths and SHA-256 provenance are recorded in `demo/CHART_SOURCES.md`. Full saved-data analysis and report export require the local research files, which are not part of this repository.

## Setup

The project was last exercised with CPython 3.14.10 and `cryptography` 50.0.2. From the repository root:

```sh
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements/asymmetric.txt -r requirements/symmetric.txt
```

The two requirement files include the shared pinned analysis dependencies. The environment version above describes the recorded project setup; compatibility with other Python/platform combinations has not been established here.

## Tests

For a public clone, run the demo and core cryptographic tests from the repository root:

```sh
python -m unittest discover -s tests -p 'test_demo.py' -v
python -m unittest discover -s tests -p 'test_hashing.py' -v
python -m unittest discover -s tests -p 'test_symmetric_crypto.py' -v
python -m unittest discover -s tests -p 'test_asymmetric_hybrid.py' -v
```

The complete test suite also includes integration checks that read existing research data under `results/`; those checks require the local research bundle. Unit tests do not replace or regenerate the saved experiments.

## Demonstrations

Each command demonstrates a short workflow using the actual repository modules. They do not report timings or access/modify research CSVs.

```sh
python -m demo.run_demo hashing
python -m demo.run_demo symmetric
python -m demo.run_demo hybrid
```

The hashing demo compares a modified message with a trusted digest and contrasts that with an attacker-recomputed unkeyed digest. The AES-GCM demo shows valid decryption and rejection of a changed authentication tag. The hybrid demo shows RSA-OAEP wrapping a fresh AES key and AES-GCM protecting the payload, including rejection after tampering. The demos do not establish sender identity, replay protection, or a formal security proof.

## Presentation

The editable deck and its PDF preview are in `demo/presentation.pptx` and `demo/presentation_preview.pdf`. To build a separate preview deck without overwriting the checked-in presentation:

```sh
python3 demo/build_presentation.py --output /tmp/cosc2539-presentation-preview.pptx
```

The builder requires Pandoc and uses the presentation template and bundled chart images in `demo/assets/`; it does not need `results/`. LibreOffice can optionally render a PDF preview. See `demo/README.md` for the presentation workflow, chart provenance, run-of-show, and recording checklist.

## Running experiments and analyses

Experiment commands write new measurements and should only be run when intentionally conducting a new experiment. Choose a new output directory for each run; do not point a runner at an existing result directory. For example:

```sh
python -m hashing.experiment_runner rq1 --output-dir results/hashing/rq1/randomized_block/runs/new_run
python -m symmetric.experiment_runner rq1 --output-dir results/symmetric/rq1/runs/new_run
python -m asymmetric.experiment_runner rq1 --output-dir results/asymmetric/rq1/runs/new_run
```

Use each runner's `--help` for available options. Experiment runners write new files under the ignored `results/` path. Analysis entry points include the package analysis modules and `python -m analysis.rq1_matched_comparative_analysis --help` / `python -m analysis.rq3_timing_magnitude_analysis --help`. The comparative analyses require the corresponding CSV inputs under local `results/`, which are not available from a fresh clone. The matched RQ1 analysis is descriptive; do not interpret those comparisons as inferential between-scheme tests.

## Known limitations

- Measurements characterize selected Python implementations on one host, not deployed industrial or resource-constrained devices.
- The three groups use different operations and timing boundaries; raw timings do not form a universal cross-category speed ranking.
- RQ1 inference is within-series and subject to the reported assumption and temporal-dependence qualifications.
- RQ3 contrasts cover complete paths and reuse valid observations across scenario contrasts; they do not isolate authentication cost or prove remote exploitability.
- Saved records do not independently establish uniqueness of every nonce/IV, and hashing backend version metadata is incomplete.

Consult the author's local report and saved outputs for full statistical qualifications, scenario definitions, and result tables.
