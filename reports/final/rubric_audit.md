# Rubric audit and revision record

**Authority:** the official requirements supplied by the student in the task message. No alternate assignment specification was sought.
**Scope:** the original 4,862-word Markdown draft was audited first; the “revision” column records what was changed for the revised Markdown/PDF. This audit does not award or predict marks.

## Requirement-by-requirement audit

| Requirement | Original draft status | Finding in the original draft | Revision / remaining action |
|---|---|---|---|
| Background and motivation (suggested 1 page) | Partially meets | Explained that hashing, symmetric encryption, and hybrid workflows do different jobs, and stated the RQs. It did not adequately justify why the selected construction families make a useful comparison. | Revised background explains the representative mechanisms and why comparisons are within category. Student should ensure the rationale matches the lecturer's framing. |
| Data collection (suggested 1 page) | Partially meets | Reported generated pseudo-random buffers, five binary sizes, 30 blocks, host metadata, warm-ups, and timing exclusions. It did not explicitly state that no outside data were scraped. | Revised section says no external dataset was scraped, explains generated inputs and matched buffers, and summarizes the data capture. |
| Experimental design and timing | Meets with caveats | Timing scopes were separated by category and block randomization described. The warm-up schedules differed across categories. | Retained this caveat. The report defines hash-only, full symmetric, and full hybrid timing scopes separately. |
| Data analysis and ANOVA (suggested 2 pages) | Partially meets | Correctly distinguished repeated-measures ANOVA from the hybrid position-adjusted CR1 OLS model and described GG correction, but the long table crowded the main argument. Diagnostics and RQ3 conditional inference needed synthesis. | Main report summarizes the six/three per-category ANOVAs and assumptions; full 15-row table is in the appendix. Friedman and CR1 OLS are described as supplementary, distinct methods. |
| Comparative results | Partially meets | Mostly listed category-level outputs; cross-category interpretation was thin and endpoint timings could be read as a ranking. | Revised RQ1-RQ3 sections compare mechanisms and results while explicitly prohibiting universal cross-category ranking claims. |
| Discussion of impact and mechanisms | Partially meets | Named some mechanisms, but did not consistently connect measured costs to digest computation, AEAD, separate CBC/HMAC passes, or hybrid key processing. | Revised discussion connects architecture to observations and labels unmeasured component costs as interpretation, not measurement. |
| Security functions and properties | Partially meets | Covered integrity and plaintext release, but the roles and limits of confidentiality, sender authentication, replay protection, and forward secrecy were not sufficiently integrated. | Revised report distinguishes hash integrity, AEAD/CBC-HMAC behavior, key establishment, sender identity, replay protection, and static-recipient-key compromise limitations. |
| Justification of choices | Partially meets | The draft described the nine algorithms but did not clearly state why those families form a useful study. | Revised background frames them as representative digest families, two AEAD constructions plus Encrypt-then-MAC, and three key-establishment/wrapping approaches with a common AES-GCM payload layer. |
| Limitations | Meets | The draft disclosed one machine, pseudo-random inputs, dependence, assumption failures, no formal proof, side-channel limits, and the Symmetric nonce/IV audit limitation. | Limitations retained. A separate evidence audit established that Hashing RQ2's documented design is 30 cases and the saved CSV is complete; the earlier 90-row cross-category expectation was unsupported. |
| IEEE citation style | Does not meet | The original reference numbers did not follow first appearance in text. | References were renumbered by first citation and formatted as numbered IEEE-style entries. Automated checks must still be reviewed by the student for any lecturer-specific punctuation preferences. |
| Reference count and diversity | Meets | The original draft had 19 references across academic/statistical publications, NIST standards, RFCs, and official library documentation. | Retained 19 references; each citation is checked against a matching entry and every entry is cited. |
| AI disclosure | Does not meet | It disclosed general use but did not place AI citations in AI-assisted sections using the required prompt citation form. | Revised report marks AI-assisted sections [AI-1] and includes the required citation template in Acknowledgements. Exact prompt(s), model/version, and date remain student placeholders. |
| Page count and file format | Does not meet | Original was Markdown only, about 4,862 words; there was no rendered page count or PDF. A word-count estimate cannot verify 5-10 pages. | Revised PDF is 11 pages total, with 8 main-report pages and 3 appendix pages. The 8-page main report meets the supplied 5-10 page range. Student must confirm any course template requirements not specified in the supplied brief. |
| Presentation, 5-6 minutes and face plus screen | Requires student input | No presentation plan existed and no video was produced. | A 5:45 demonstration plan is supplied. The student must perform/record it with both face and screen visible and submit via YouTube or Canvas. |
| Weekly instructor feedback | Requires student input | The repository contains no evidence of weekly in-depth tutorial feedback requests. | Not addressed by report editing. Student must seek feedback as required; no score improvement is claimed. |
| Individual assessment, 20%, deadline | Requires student input | These administrative facts do not affect the technical analysis. | Student must submit individually by 22 November 2026, 23:59, following Canvas submission instructions. |

## Evidence count audit

| Category | RQ1 expected / observed | RQ2 expected / observed | RQ3 expected / observed |
|---|---:|---:|---:|
| Hashing | 450 / 450 | 30 / 30 (3 algorithms × 5 sizes × 2 scenarios) | 1,350 / 1,350 |
| Symmetric | 900 / 900 | 90 / 90 | 2,700 / 2,700 (corrected raw run run_20261119_02) |
| Asymmetric-based hybrid | 900 / 900 | 85 / 85 | 2,250 / 2,250 |

The Hashing RQ2 baseline has 15 records for each of two tampering scenarios (three algorithms by five sizes), with one functional check per configuration. It has no separate valid-data case. Its RQ3 CSV has three timing scenarios and 1,350 rows; those outcomes remain associated with the RQ3 timing run and are not added to RQ2's functional count. The previous cross-category table's expectation of 90 Hashing RQ2 cases had no basis in the documented design and has been corrected.

## Overall assessment

The revised report now addresses the technical and comparative expectations in the supplied written-report rubric, subject to student review. It has 8 main pages (references included, appendix excluded) and 11 PDF pages total. The Hashing RQ2 count is resolved as 30 complete functional configurations. AI citation placeholders remain. Final submission still requires the student to complete identity fields, exact AI citations, and the demonstration video. Weekly-feedback marks are outside this editing task.

