"""Outils simples d'introspection de l'état d'exécution."""

from typing import Any


def audit_runtime_state(tag: str = "audit") -> dict[str, Any]:
    """Retourne un aperçu des noms globaux et des variables locales."""
    return {
        "tag": tag,
        "globals_keys": list(globals().keys()),
        "locals_snapshot": dict(locals()),
    }
