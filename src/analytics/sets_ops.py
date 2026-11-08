"""Opérations sur les ensembles d'adresses IP issues des logs."""

from collections.abc import Iterable, Mapping
from typing import Any


# Ensemble immuable des adresses IP interdites fourni par le cahier des charges.
BLACKLIST: frozenset[str] = frozenset({"10.0.0.1", "192.168.1.66"})


def unique_error_ips(logs: Iterable[Mapping[str, Any]]) -> set[str]:
    """Retourne les adresses IP distinctes ayant produit un log de niveau ERROR."""
    error_ips: set[str] = set()

    for log in logs:
        if not isinstance(log, Mapping):
            continue

        level = str(log.get("level", "")).strip().upper()
        src_ip = log.get("src_ip")

        if level == "ERROR" and isinstance(src_ip, str) and src_ip.strip():
            error_ips.add(src_ip.strip())

    return error_ips


def ip_set_analysis(active_ips: set[str]) -> dict[str, set[str]]:
    """Compare les IP actives à la blacklist avec les opérations sur les sets."""
    return {
        "blacklisted_active": active_ips & BLACKLIST,
        "all_known": active_ips | BLACKLIST,
        "clean_active": active_ips - BLACKLIST,
        "exclusives": active_ips ^ BLACKLIST,
    }
