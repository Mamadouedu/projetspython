"""Détection de tentatives de connexion répétées (force brute)."""

import json
from collections import defaultdict
from collections.abc import Iterable, Mapping
from typing import Any

FAILED_STATUSES = frozenset({"failed", "failure"})


def detect_bruteforce(
    logs: Iterable[Mapping[str, Any]], threshold: int = 5
) -> list[str]:
    """Retourne les IP ayant atteint ``threshold`` échecs de login consécutifs.

    Les tentatives sont suivies séparément pour chaque IP. Un événement de login
    dont le statut n'est pas un échec remet le compteur de cette IP à zéro.
    Les événements qui ne sont pas des tentatives de login sont ignorés.

    Le champ ``payload`` peut être un dictionnaire ou une chaîne JSON, comme
    dans le format de log présenté dans le cahier des charges. Les résultats
    sont uniques et conservés dans l'ordre de première détection.
    """
    if threshold < 1:
        raise ValueError("threshold doit être supérieur ou égal à 1")

    failures_by_ip: defaultdict[str, int] = defaultdict(int)
    detected_ips: list[str] = []
    detected_set: set[str] = set()

    iterator = iter(logs)
    sentinel = object()

    # Le while consomme l'itérable progressivement : aucun chargement global.
    # Le else du while s'exécute quand l'itérable est arrivé normalement à la fin.
    while (log := next(iterator, sentinel)) is not sentinel:
        if not isinstance(log, Mapping):
            continue

        src_ip = log.get("src_ip")
        if not isinstance(src_ip, str) or not src_ip.strip():
            continue
        src_ip = src_ip.strip()

        payload: Any = log.get("payload", {})
        if isinstance(payload, str):
            try:
                payload = json.loads(payload)
            except json.JSONDecodeError:
                payload = {}

        if not isinstance(payload, Mapping):
            payload = {}

        # On cherche les champs d'événement dans payload, puis dans le log.
        # Le break arrête la recherche dès qu'une source contient action/status.
        for candidate in (payload, log):
            if isinstance(candidate, Mapping) and (
                "action" in candidate or "status" in candidate
            ):
                event_data = candidate
                break
        else:
            # Aucun champ action/status : ce log ne décrit pas un événement utile.
            continue

        action = str(event_data.get("action", log.get("action", ""))).strip().lower()
        status = str(event_data.get("status", log.get("status", ""))).strip().lower()

        if action != "login":
            continue

        if status in FAILED_STATUSES:
            failures_by_ip[src_ip] += 1
            if failures_by_ip[src_ip] >= threshold and src_ip not in detected_set:
                detected_ips.append(src_ip)
                detected_set.add(src_ip)
        else:
            # Une tentative de login non échouée interrompt la série d'échecs.
            failures_by_ip[src_ip] = 0

    return detected_ips

    # Cette instruction est une sécurité de repli ; le while se termine
    # normalement par son else dans le fonctionnement attendu.
    return detected_ips
