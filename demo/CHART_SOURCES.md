# Presentation Chart Sources

Only existing report figures are embedded as charts. The presentation source references the files directly; no copies, crops, value changes, or redraws are made.

| Slide | Source path | Research question | What it communicates | Slide treatment |
|---|---|---|---|---|
| 6 | `results/symmetric/rq1/analysis/run_20261119_02/symmetric_rq1_execution_time.png` | RQ1 | Mean Symmetric encryption and decryption times across all five payload sizes for AES-256-GCM, ChaCha20-Poly1305, and CBC-HMAC. The plotted profiles rise with size; the report does not infer between-scheme significance from them. | Embedded at its original aspect ratio, scaled to slide width. No data or image edits. |
| 8 | `results/symmetric/rq3/analysis/run_20261119_03/symmetric_rq3_execution_time.png` | RQ3 | Corrected-run Symmetric complete decryption-path means across valid and specified invalid scenarios and five payload sizes. It illustrates that scenarios can stop at different processing stages. | Embedded at its original aspect ratio, scaled to slide width. No data or image edits. |

## Relevant existing assets not selected

- `results/asymmetric/rq1/analysis/run_20261119_01/asymmetric_rq1_execution_time.png` is Figure B1 in the report. It contains six panels in a square, making its small multiples less readable at presentation scale; its RQ1 means are described verbally instead.
- `results/hashing/rq1/baseline/hashing_execution_time.png` depicts the legacy sequential baseline, not the randomized-block Hashing RQ1 dataset used by the final report, so it is excluded.
- The available Hashing randomized-block PNGs are diagnostics, not performance charts: `results/hashing/rq1/randomized_block/hashing_randomized_block_diagnostics.png` and `results/hashing/rq1/randomized_block/repeated_measures/hashing_repeated_measures_diagnostics.png`.
- The final report has no RQ2 chart. Slide 7 uses the report's functional-outcome counts, supported by the RQ2 records listed in `AUDIT.md`; it does not reconstruct a chart.
- Other RQ3 plots exist for Hybrid and older Symmetric runs. The selected Symmetric plot is the corrected run identified in the final report. Hashing RQ3 has no corresponding PNG in the report assets.

## Readability

Both selected PNGs are 2080×800 and 2720×800 pixels respectively. Their axes, legends, and units are legible in the original report figures and are embedded with preserved aspect ratios. The generated PDF slide preview is the final check for presentation-scale readability.
