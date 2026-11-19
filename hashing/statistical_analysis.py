"""Analyze Hashing RQ1 and RQ3 data used by the final report."""

import argparse
from pathlib import Path

from hashing.repeated_measures_analysis import (
    DEFAULT_ALPHA,
    analyze_repeated_measures,
    write_descriptive_statistics,
)
from hashing.tampering_performance_analysis import (
    PERMUTATIONS,
    analyze_tampering_performance,
)


def analyze_rq1(
    input_csv: str | Path,
    output_dir: str | Path,
    alpha: float = DEFAULT_ALPHA,
) -> dict:
    """Write report-used descriptives and repeated-measures analysis outputs."""
    descriptive_path = write_descriptive_statistics(input_csv, output_dir)
    statistical_outputs = analyze_repeated_measures(input_csv, output_dir, alpha)
    return {"descriptive_csv": descriptive_path, **statistical_outputs}


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Analyze Hashing results used by the final report."
    )
    subparsers = parser.add_subparsers(dest="research_question", required=True)

    rq1 = subparsers.add_parser("rq1", help="repeated-measures size analysis")
    rq1.add_argument(
        "--input-csv",
        type=Path,
        default=Path("results/hashing/rq1/randomized_block")
        / "hashing_randomized_block_benchmarks.csv",
    )
    rq1.add_argument(
        "--output-dir",
        type=Path,
        default=Path("results/hashing/rq1/randomized_block/analysis/new_run"),
    )
    rq1.add_argument("--alpha", type=float, default=DEFAULT_ALPHA)

    rq3 = subparsers.add_parser("rq3", help="matched tampering-time analysis")
    rq3.add_argument(
        "--input-csv",
        type=Path,
        default=Path("results/hashing/rq3/tampering_performance")
        / "hashing_tampering_performance.csv",
    )
    rq3.add_argument(
        "--metadata", type=Path, default=None, help="defaults to metadata beside the CSV"
    )
    rq3.add_argument(
        "--output-dir",
        type=Path,
        default=Path("results/hashing/rq3/tampering_performance/analysis/new_run"),
    )
    rq3.add_argument("--seed", type=int, default=55)
    rq3.add_argument("--permutations", type=int, default=PERMUTATIONS)
    rq3.add_argument("--minimum-blocks", type=int, default=30)

    args = parser.parse_args()
    if args.research_question == "rq1":
        outputs = analyze_rq1(args.input_csv, args.output_dir, args.alpha)
    else:
        outputs = analyze_tampering_performance(
            args.input_csv,
            args.output_dir,
            seed=args.seed,
            permutation_count=args.permutations,
            minimum_blocks=args.minimum_blocks,
            metadata_path=args.metadata,
        )
    for name, path in outputs.items():
        print(f"{name}: {path}")


if __name__ == "__main__":
    main()
