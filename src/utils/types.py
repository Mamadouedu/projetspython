"""Types partagés du projet.

Expose :
- `Severity` : enum des niveaux de sévérité.
- `LogEntry` : TypedDict représentant un log parsé.
- `ConnectionMeta` : tuple immuable (IP, Port, Protocole).
"""
from __future__ import annotations

from enum import Enum
from typing import Any, TypedDict


class Severity(str, Enum):
    """Niveaux de sévérité d'un log, par ordre croissant."""

    INFO = "INFO"
    WARNING = "WARNING"
    ERROR = "ERROR"
    CRITICAL = "CRITICAL"


VALID_LEVELS: frozenset[str] = frozenset(s.value for s in Severity)


class LogEntry(TypedDict):
    """Un log parsé, structuré sous forme de dict."""

    timestamp: str
    level: str
    src_ip: str
    user_id: str
    payload: Any  # dict (JSON), str (brut) ou tuple (connexion)


# Métadonnée fixe immuable (tuple) : (IP, Port, Protocole).
ConnectionMeta = tuple[str, int, str]
