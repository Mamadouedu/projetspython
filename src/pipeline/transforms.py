"""Module 2.2 — Normalisation des logs avec map() et des f-strings.

On nettoie chaque log pour que tous aient le même format :
- niveau en MAJUSCULES       : " warning " -> "WARNING"
- utilisateur en minuscules  : " Bob "     -> "bob"
- timestamp sans les fractions de seconde :
  "2026-11-01T10:00:00.123456Z" -> "2026-11-01T10:00:00Z"
- espaces inutiles retirés partout
"""
from __future__ import annotations

from collections.abc import Iterable, Iterator

from src.utils.types import LogEntry


# ---------------------------------------------------------------------------
# 1. Reformater le timestamp avec une f-string
# ---------------------------------------------------------------------------
def format_timestamp(ts: str) -> str:
    """Retire les fractions de seconde d'un timestamp.

    "2026-11-01T10:00:00.123456Z" -> "2026-11-01T10:00:00Z"
    "2026-11-01T10:00:00Z"        -> "2026-11-01T10:00:00Z" (déjà propre)
    """
    ts = ts.strip().rstrip("Z")  # "2026-11-01T10:00:00.123456"
    sans_fraction = ts.split(".")[0]  # "2026-11-01T10:00:00"
    return f"{sans_fraction}Z"  # on remet le Z à la fin


# ---------------------------------------------------------------------------
# 2. Nettoyer UN log
# ---------------------------------------------------------------------------
def clean_log(log: LogEntry) -> LogEntry:
    """Renvoie une copie propre du log (le log d'origine n'est pas modifié)."""
    payload = log["payload"]
    if isinstance(payload, str):
        payload = payload.strip()  # on nettoie seulement le texte brut

    level = log["level"].strip().upper()
    src_ip = log["src_ip"].strip()
    user_id = log["user_id"].strip().lower()

    return {
        "timestamp": format_timestamp(log["timestamp"]),
        "level": level,
        "src_ip": src_ip,
        "user_id": user_id,
        "payload": payload,
        # Résumé lisible construit avec une f-string :
        # :<8 aligne le niveau à gauche sur 8 caractères.
        "summary": f"[{level:<8}] {user_id} @ {src_ip}",
    }


# ---------------------------------------------------------------------------
# 3. Nettoyer TOUS les logs avec map()
# ---------------------------------------------------------------------------
def normalize(logs: Iterable[LogEntry]) -> Iterator[LogEntry]:
    """Applique clean_log à chaque log avec map() (paresseux)."""
    return map(clean_log, logs)
