"""Point d'entrée CLI du pipeline (stub Dev A — sera étendu par Dev B).

Lit un fichier de logs via les générateurs du Module 1, parse chaque
ligne, et affiche les premières entrées valides ainsi que des stats
de rejet.

Usage :

    python main.py --input data/sample_small.log --limit 10
"""
from __future__ import annotations

import argparse
from pathlib import Path

from src.ingestion.log_generator import read_log_file
from src.ingestion.parser import parse_line


def main() -> None:
    parser = argparse.ArgumentParser(description="Pipeline de logs sécurisé")
    parser.add_argument(
        "--input",
        type=Path,
        required=True,
        help="Fichier de logs à ingérer.",
    )
    parser.add_argument(
        "--limit",
        type=int,
        default=10,
        help="Nombre d'entrées valides à afficher.",
    )
    args = parser.parse_args()

    shown = 0
    kept = 0
    dropped = 0

    for raw in read_log_file(args.input):
        entry = parse_line(raw)
        if entry is None:
            dropped += 1
            continue
        kept += 1
        if shown < args.limit:
            print(entry)
            shown += 1

    total = kept + dropped
    pct = 100 * dropped / max(total, 1)
    print(
        f"\n[main] {kept:,} valides · {dropped:,} rejetées "
        f"({pct:.1f} % sales) · {total:,} lignes au total"
    )


if __name__ == "__main__":
    main()
