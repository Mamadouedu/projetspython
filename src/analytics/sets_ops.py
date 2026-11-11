"""Opérations sur les ensembles d'adresses IP issues des logs."""

from collections.abc import Iterable, Mapping
from typing import Any

# Ensemble immuable des adresses IP interdites.
# Doit correspondre aux 12 premières IPs produites par scripts/generate_logs.py
# (variable BLACKLIST_IPS = IPS[:12] du générateur), sinon ip_set_analysis
# renvoie un `blacklisted_active` vide sur le vrai dataset.
BLACKLIST: frozenset[str] = frozenset(
    {
        "192.168.1.1",
        "192.168.1.2",
        "192.168.1.3",
        "192.168.1.4",
        "192.168.1.5",
        "192.168.1.6",
        "192.168.1.7",
        "192.168.1.8",
        "192.168.1.9",
        "192.168.1.10",
        "192.168.1.11",
        "192.168.1.12",
    }
)


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
