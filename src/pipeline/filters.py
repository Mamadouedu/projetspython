"""Module 2.1 — Filtrage des logs avec filter() et lambda.

Chaque fonction reçoit un flux de logs et renvoie un flux filtré.
Rien n'est calculé tant qu'on ne parcourt pas le résultat (filtrage paresseux).
"""

from __future__ import annotations

from collections.abc import Iterable, Iterator

from src.utils.types import LogEntry


# ---------------------------------------------------------------------------
# 1. Retirer les lignes sales
# ---------------------------------------------------------------------------
def drop_invalid(entries: Iterable[LogEntry | None]) -> Iterator[LogEntry]:
    """Retire les lignes que le parser n'a pas réussi à lire.

    Le parser renvoie None pour une ligne sale.
    filter(None, ...) garde seulement les éléments "vrais", donc retire les None.
    """
    return filter(None, entries)


# ---------------------------------------------------------------------------
# 2. Retirer les requêtes invalides (prédicat personnalisé)
# ---------------------------------------------------------------------------
def is_valid_request(log: LogEntry) -> bool:
    """Renvoie True si le payload du log est utilisable.

    Cas invalides :
    - payload vide : {} ou ""
    - JSON cassé : le parser n'arrive pas à le lire et le garde en texte,
      donc un texte qui commence par "{" ou "[" est un JSON mal formé.
    """
    payload = log["payload"]

    if not payload:  # {} , "" , None
        return False

    # Un texte qui commence par "{" ou "[" est un JSON cassé resté en str.
    return not (isinstance(payload, str) and payload.startswith(("{", "[")))


def drop_invalid_requests(logs: Iterable[LogEntry]) -> Iterator[LogEntry]:
    """Garde seulement les logs dont la requête est valide."""
    return filter(lambda log: is_valid_request(log), logs)


# ---------------------------------------------------------------------------
# 3. Filtres simples avec lambda
# ---------------------------------------------------------------------------
def by_level(logs: Iterable[LogEntry], level: str) -> Iterator[LogEntry]:
    """Garde les logs d'un niveau donné (ex : "ERROR")."""
    return filter(lambda log: log["level"] == level, logs)


def by_ip(logs: Iterable[LogEntry], ip: str) -> Iterator[LogEntry]:
    """Garde les logs venant d'une adresse IP donnée."""
    return filter(lambda log: log["src_ip"] == ip, logs)


def failed_logins(logs: Iterable[LogEntry]) -> Iterator[LogEntry]:
    """Garde les connexions échouées.

    Payload attendu : {"action": "login", "status": "failed"}
    """
    return filter(
        lambda log: isinstance(log["payload"], dict)
        and log["payload"].get("action") == "login"
        and log["payload"].get("status") == "failed",
        logs,
    )
