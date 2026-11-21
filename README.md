# COSC2539 / COSC2716 — Cryptography Under Adversarial Conditions

This repository contains a Python implementation-level study of selected cryptographic constructions under controlled payload-size and tampering conditions. It includes the implementations, experiment runners, saved research evidence, analysis, tests, and a short demonstration/presentation. It is not a benchmark of deployed IoT devices or a complete industrial security assessment.

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

The project's main contributions are the Python implementations, randomized-block experiment runners, analysis scripts, automated tests, matched descriptive RQ1 comparisons, RQ3 timing-magnitude analysis, and a demonstration wrapper that calls the project implementations. The available raw observations and saved analysis results are retained under `results/` with their category-specific paths.

The five payload sizes were 1 KiB, 10 KiB, 100 KiB, 1 MiB, and 10 MiB, with 30 measured blocks; five warm-up executions were excluded from measurement. Warm-up scheduling differs by category and is documented with the saved metadata and local report. The experiments were conducted on one host and do not measure IoT-device energy, memory, network latency, or deployed protocol behavior. Some statistical assumptions and temporal-independence diagnostics require caution. See the saved result metadata and the report retained in the author's local workspace for the detailed methods and limitations.

## Repository layout

```text
hashing/                         Hashing implementations, runners, and analysis
symmetric/                       Symmetric implementations, runners, and analysis
asymmetric/                      Asymmetric-based hybrid implementations and analysis
tests/                            Automated functional and analysis tests
requirements/                     Pinned dependency sets
results/                          Raw observations, metadata, saved analyses, and figures
demo/                             Demo wrapper, slide source, presentation, and script
rq1_matched_comparative_analysis.py
rq3_timing_magnitude_analysis.py
```

The Markdown report and its DOCX/PDF exports are intentionally kept in the author's local `reports/` directory and are excluded from this repository's current Git tracking. `AGENTS.md` and internal audit notes are also local-only. The `results/` directory remains tracked because it provides the evidence used by the analyses and presentation; it contains generated research data, not a fresh experiment run by installation or tests.

## Setup

The project was last exercised with CPython 3.14.10 and `cryptography` 50.0.2. From the repository root:

```sh
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements/asymmetric.txt -r requirements/symmetric.txt
```

The two requirement files include the shared pinned analysis dependencies. The environment version above describes the recorded project setup; compatibility with other Python/platform combinations has not been established here.

## Tests

Run the functional and analysis unit tests from the repository root:

```sh
python -m unittest discover -s tests -v
```

The suite includes small runner checks with test-sized inputs; it does not run the full experiment suites or overwrite saved research results.

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

The builder requires Pandoc and uses the presentation template and chart files already in the repository. LibreOffice can optionally render a PDF preview. See `demo/README.md` for the presentation workflow, chart provenance, run-of-show, and recording checklist.

## Running experiments and analyses

Experiment commands write new measurements and should only be run when intentionally conducting a new experiment. Choose a new output directory for each run; do not point a runner at an existing result directory. For example:

```sh
python -m hashing.experiment_runner rq1 --output-dir results/hashing/rq1/randomized_block/runs/new_run
python -m symmetric.experiment_runner rq1 --output-dir results/symmetric/rq1/runs/new_run
python -m asymmetric.experiment_runner rq1 --output-dir results/asymmetric/rq1/runs/new_run
```

Use each runner's `--help` for available options. Analysis entry points include `python -m hashing.statistical_analysis --help`, the corresponding package analysis modules, and the root RQ1/RQ3 descriptive scripts. Analysis output directories should also be new and distinct from saved authoritative outputs. The matched RQ1 analysis is descriptive; do not interpret those comparisons as inferential between-scheme tests.

## Known limitations

- Measurements characterize selected Python implementations on one host, not deployed industrial or resource-constrained devices.
- The three groups use different operations and timing boundaries; raw timings do not form a universal cross-category speed ranking.
- RQ1 inference is within-series and subject to the reported assumption and temporal-dependence qualifications.
- RQ3 contrasts cover complete paths and reuse valid observations across scenario contrasts; they do not isolate authentication cost or prove remote exploitability.
- Saved records do not independently establish uniqueness of every nonce/IV, and hashing backend version metadata is incomplete.

Consult the local report and saved outputs for full statistical qualifications and scenario definitions.
