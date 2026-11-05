"""Parsing d'une ligne de log en LogEntry structuré.

Format attendu :

    <timestamp ISO8601> | <level> | <ip> | user=<id> | <payload>

où `payload` peut être :
- un objet JSON (ex. `{"action": "login", "status": "failed"}`)
- un tuple de connexion `(IP, Port, Protocole)`
- une chaîne brute

Le parseur est **tolérant aux lignes sales** (consigne prof) : il renvoie
`None` pour toute ligne invalide (vide, commentaire, mal formée, timestamp
invalide, IP invalide, niveau inconnu, user manquant), ce qui permet au
module 2 de les filtrer facilement avec `filter(None, ...)`.
"""
from __future__ import annotations

import json
import re
from typing import Any, Optional

from src.utils.types import VALID_LEVELS, LogEntry

_IP_RE = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}$")
_TIMESTAMP_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z$")


def _is_valid_ip(ip: str) -> bool:
    if not _IP_RE.match(ip):
        return False
    try:
        return all(0 <= int(part) <= 255 for part in ip.split("."))
    except ValueError:
        return False


def _parse_payload(raw: str) -> Any:
    """Transforme la portion payload en dict / tuple / str.

    Tente dans l'ordre : tuple de connexion, JSON, puis chaîne brute en
    dernier recours.
    """
    s = raw.strip()
    if not s:
        return ""

    # Tuple de connexion : (IP, PORT, PROTO)
    if s.startswith("(") and s.endswith(")"):
        inner = s[1:-1]
        parts = [p.strip() for p in inner.split(",")]
        if len(parts) == 3 and _is_valid_ip(parts[0]):
            try:
                return (parts[0], int(parts[1]), parts[2])
            except ValueError:
                pass

    # JSON
    if s.startswith("{") or s.startswith("["):
        try:
            return json.loads(s)
        except json.JSONDecodeError:
            pass

    # Chaîne brute
    return s


def parse_line(line: str | None) -> Optional[LogEntry]:
    """Parse une ligne de log en LogEntry.

    Retourne `None` si la ligne est sale ou invalide, pour qu'elle soit
    écartée par `filter(None, ...)` dans le pipeline.
    """
    if line is None:
        return None

    s = line.strip()
    if not s or s.startswith("#"):
        return None

    parts = [p.strip() for p in s.split("|")]
    if len(parts) < 5:
        return None

    timestamp = parts[0]
    level = parts[1]
    src_ip = parts[2]
    user_field = parts[3]
    # Un payload peut contenir des `|` (ex. dans une chaîne brute) → on
    # rejoint tout ce qui vient après le 4e séparateur.
    payload_raw = "|".join(parts[4:]).strip()

    if not _TIMESTAMP_RE.match(timestamp):
        return None
    if level not in VALID_LEVELS:
        return None
    if not _is_valid_ip(src_ip):
        return None
    if not user_field.startswith("user="):
        return None

    user_id = user_field[len("user=") :].strip()
    if not user_id:
        return None

    return LogEntry(
        timestamp=timestamp,
        level=level,
        src_ip=src_ip,
        user_id=user_id,
        payload=_parse_payload(payload_raw),
    )
