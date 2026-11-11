"""Module 2.3 — Analyse de structure avec match-case.

On regarde le format du payload de chaque log pour savoir où l'envoyer :
- tuple de connexion : (IP, Port, Protocole)  -> "connexion"
- dictionnaire       : {"level": ..., "code": ...} ou autre dict -> "dictionnaire"
- chaîne brute       : "raw event 1234"        -> "brut"
- autre chose        :                          -> "inconnu"

match-case remplace une longue suite de if / elif / else.
"""

from __future__ import annotations

from collections.abc import Iterable, Iterator
from typing import Any

from src.utils.types import LogEntry


# ---------------------------------------------------------------------------
# 1. Trouver le format d'un log
# ---------------------------------------------------------------------------
def get_route(log: LogEntry) -> str:
    """Renvoie le format du payload du log grâce à match-case."""
    match log["payload"]:
        # Tuple de connexion : 3 éléments (texte, nombre, texte)
        case (str(), int(), str()):
            return "connexion"

        # Dictionnaire d'erreur serveur : on CAPTURE la valeur de "code" dans la
        # variable `code`, puis la garde `if` la teste.
        # ex : {"level": "ERROR", "code": 500}
        case {"level": str(), "code": int(code)} if code >= 500:
            return "dictionnaire"

        # N'importe quel autre dictionnaire, ex : {"action": "login", "status": "ok"}
        case dict():
            return "dictionnaire"

        # Chaîne de texte brute
        case str():
            return "brut"

        # Tout le reste
        case _:
            return "inconnu"


# ---------------------------------------------------------------------------
# 2. Ajouter le format à chaque log du flux
# ---------------------------------------------------------------------------
def add_route(log: LogEntry) -> dict[str, Any]:
    """Renvoie une copie du log avec une clé "route" en plus."""
    return {**log, "route": get_route(log)}


def route_logs(logs: Iterable[LogEntry]) -> Iterator[dict[str, Any]]:
    """Applique add_route à chaque log avec map() (paresseux)."""
    return map(add_route, logs)
