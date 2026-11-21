# Presentation Chart Sources

The presentation uses two byte-for-byte copies of existing generated figures under `demo/assets/`. This lets a fresh clone view and build the deck without the local-only `results/` directory. The underlying CSV files and analysis metadata remain local-only; their original paths and recorded checksums are retained here for provenance. No chart data were reconstructed or changed for this packaging step.

| Slide | Bundled asset (SHA-256) | Original generated figure | Source CSV and recorded SHA-256 | Meaning |
|---|---|---|---|---|
| 6 | `demo/assets/symmetric_rq1_execution_time.png` — `4db0761e6fe95799c6dff0936c813cb65eb5b342b62cba97e3caecbb0c20b76a` | `results/symmetric/rq1/analysis/run_20261119_02/symmetric_rq1_execution_time.png` | `results/symmetric/rq1/runs/run_20261119_01/symmetric_rq1_benchmarks.csv` — `52d6fa1949d1b131a18c5576faf5c19c6f30c5b0e0de16f0a81a86c822edc4b4` | RQ1 Symmetric-category mean encryption/decryption times across five payload sizes. Descriptive only; no between-scheme significance test is represented. |
| 8 | `demo/assets/symmetric_rq3_execution_time.png` — `34c8af9008ec6b9aa114cd115222cdc220246de3a1463142165c8743579b2450` | `results/symmetric/rq3/analysis/run_20261119_03/symmetric_rq3_execution_time.png` | `results/symmetric/rq3/runs/run_20261119_02/symmetric_rq3_verification.csv` — `428c62fb7321cdb868c3aa60aa3c5d88ee9bae2366689c634d8f8727c5dbc4c3` | Corrected-run Symmetric complete decryption-path means for valid and specified invalid scenarios across five payload sizes. The single shared scenario legend is above the 1×3 panels. |

The source CSV paths and checksums above were verified against the local analysis metadata: `results/symmetric/rq1/analysis/run_20261119_02/symmetric_rq1_summary.json` and `results/symmetric/rq3/analysis/run_20261119_03/symmetric_rq3_summary.json`. The RQ1 file is the recorded run `run_20261119_01`; the corrected RQ3 file is `run_20261119_02`, with superseded run `run_20261119_01` excluded. RQ3 metadata records 2,700 raw observations and 75 paired contrasts.

Slide 6 displays the Symmetric category only. Its visible caption states that all 15 within-series RQ1 tests were Holm-significant and that no between-scheme significance tests were conducted. Slide 8 shows one category's complete decryption-path timing and should not be interpreted as isolated authentication cost or as evidence of a remotely exploitable timing side channel.

The original RQ1 and RQ3 CSVs, analysis outputs, and `results/` figures are not included in a public clone. The checksums are provenance metadata; they do not make those local-only data files independently available.
