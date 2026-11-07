"""Benchmark mémoire du pipeline d'ingestion (Dev A).

Prouve, via `tracemalloc`, que l'approche générateur (`yield` + `yield from`)
lit un fichier arbitrairement gros sans jamais faire exploser la RAM.

Sortie :
- Taille du fichier d'entrée.
- Nombre de lignes lues / valides / rejetées.
- Pic de mémoire allouée côté Python (en Mo).
- Débit (Mo/s, lignes/s).

Usage :

    python scripts/bench_memory.py --input data/sample_small.log
    python scripts/bench_memory.py --input data/sample_large.log
"""
from __future__ import annotations

import argparse
import sys
import time
import tracemalloc
from pathlib import Path

# Rendre le package `src` importable quand on lance ce script depuis `scripts/`.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from src.ingestion.log_generator import read_log_file  # noqa: E402
from src.ingestion.parser import parse_line  # noqa: E402


def bench(path: Path, read_only: bool = False) -> dict[str, float | int]:
    """Lit (et parse si demandé) l'intégralité du fichier, mesure RAM et temps.

    `read_only=True` saute l'étape parsing — mesure la seule lecture via
    `yield` + `yield from`. Utile pour prouver la non-saturation RAM à
    grande échelle en quelques minutes seulement.
    """
    if not path.exists():
        raise FileNotFoundError(f"Fichier introuvable : {path}")

    file_size = path.stat().st_size

    tracemalloc.start()
    t0 = time.perf_counter()

    total = kept = dropped = 0
    for raw in read_log_file(path):
        total += 1
        if read_only:
            continue
        entry = parse_line(raw)
        if entry is None:
            dropped += 1
        else:
            kept += 1

    elapsed = time.perf_counter() - t0
    current, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()

    return {
        "file_size_mb": file_size / 1024**2,
        "file_size_gb": file_size / 1024**3,
        "total_lines": total,
        "kept": kept,
        "dropped": dropped,
        "elapsed_s": elapsed,
        "mem_current_mb": current / 1024**2,
        "mem_peak_mb": peak / 1024**2,
        "throughput_mb_s": (file_size / 1024**2) / elapsed if elapsed > 0 else 0.0,
        "throughput_lines_s": total / elapsed if elapsed > 0 else 0.0,
        "mode": "read-only" if read_only else "read+parse",
    }


def _fmt_int(n: int) -> str:
    return f"{n:,}".replace(",", " ")


def print_report(path: Path, stats: dict[str, float | int]) -> None:
    print(f"\n{'=' * 60}")
    print(f"  BENCH MÉMOIRE — {path}  [{stats['mode']}]")
    print(f"{'=' * 60}")
    print(f"  Fichier          : {stats['file_size_gb']:.3f} Go "
          f"({stats['file_size_mb']:.1f} Mo)")
    print(f"  Lignes totales   : {_fmt_int(int(stats['total_lines']))}")
    if stats["mode"] == "read+parse":
        pct_dropped = 100 * stats["dropped"] / max(stats["total_lines"], 1)
        print(f"  Valides          : {_fmt_int(int(stats['kept']))}")
        print(f"  Rejetées (sales) : {_fmt_int(int(stats['dropped']))} "
              f"({pct_dropped:.1f} %)")
    print(f"  Temps            : {stats['elapsed_s']:.2f} s")
    print(f"  Débit            : {stats['throughput_mb_s']:.1f} Mo/s "
          f"— {_fmt_int(int(stats['throughput_lines_s']))} lignes/s")
    print(f"{'-' * 60}")
    print(f"  Mémoire finale   : {stats['mem_current_mb']:.3f} Mo")
    print(f"  Mémoire PIC      : {stats['mem_peak_mb']:.3f} Mo")
    print(f"{'=' * 60}")

    # Ratio fichier / RAM : prouve la non-saturation
    if stats["mem_peak_mb"] > 0:
        ratio = stats["file_size_mb"] / stats["mem_peak_mb"]
        print(f"  Ratio taille fichier / RAM pic : {ratio:,.0f}x")
        if ratio > 100:
            print(f"  VERDICT : générateur tient la charge (ratio > 100x)")
        else:
            print(f"  ATTENTION : ratio faible, vérifier qu'il n'y a pas "
                  "d'accumulation en mémoire")
    print()


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Bench mémoire du pipeline d'ingestion"
    )
    parser.add_argument(
        "--input",
        type=Path,
        required=True,
        help="Fichier de logs à parcourir.",
    )
    parser.add_argument(
        "--read-only",
        action="store_true",
        help="Mesure uniquement la lecture (yield), sans parser — très rapide.",
    )
    args = parser.parse_args()

    stats = bench(args.input, read_only=args.read_only)
    print_report(args.input, stats)


if __name__ == "__main__":
    main()
