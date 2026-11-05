"""Lecture paresseuse de fichiers de logs via générateurs.

Objectif : traverser des fichiers volumineux (10-15 Go) sans jamais
charger l'intégralité en RAM.

- `read_log_file(path)` est un **générateur** (`yield`) qui émet chaque
  ligne du fichier à la demande.
- `read_multiple_sources(paths)` est un **sous-générateur** qui délègue
  à `read_log_file` via `yield from`, pour chaîner plusieurs fichiers
  successifs en un seul flux unique.
"""
from __future__ import annotations

from pathlib import Path
from typing import Iterator, Sequence


def read_log_file(path: str | Path) -> Iterator[str]:
    """Génère les lignes d'un fichier de logs une par une.

    Utilise `yield` pour émettre chaque ligne sans jamais charger le
    fichier complet en mémoire. Les retours chariot de fin de ligne
    sont retirés. Les erreurs d'encodage sont tolérées (`errors="replace"`)
    pour ne pas planter sur une ligne corrompue.
    """
    p = Path(path)
    with p.open("r", encoding="utf-8", errors="replace") as f:
        for line in f:
            yield line.rstrip("\r\n")


def read_multiple_sources(paths: Sequence[str | Path]) -> Iterator[str]:
    """Chaîne plusieurs fichiers de logs en un flux unique.

    Utilise `yield from` pour déléguer la génération ligne par ligne
    à `read_log_file`. Idéal pour agréger plusieurs sources (ex. logs
    d'hier + logs du jour) sans concaténation sur disque.
    """
    for path in paths:
        yield from read_log_file(path)
