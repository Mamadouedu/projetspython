"""Moteur d'exécution de règles de sécurité."""

from collections.abc import Callable, Mapping
from typing import Any


def apply_security_rules(
    *args: Callable[..., Any], **kwargs: Any
) -> list[dict[str, Any]]:
    """Exécute les fonctions de règles reçues et rassemble leurs résultats.

    Chaque règle reçoit les paramètres de configuration fournis dans
    ``kwargs``. Les données à analyser peuvent notamment être transmises avec
    ``logs=...``. Chaque résultat est normalisé en dictionnaire et porte le
    nom de la règle dans la clé ``rule``.

    Exemple :
        apply_security_rules(
            check_bruteforce,
            check_blacklist,
            logs=logs,
            threshold=5,
            mode="strict",
        )

    Les fonctions de règle doivent accepter les paramètres partagés qui leur
    sont transmis, ou déclarer ``**kwargs`` pour les recevoir.
    """
    results: list[dict[str, Any]] = []

    for rule in args:
        if not callable(rule):
            raise TypeError(f"La règle {rule!r} n'est pas appelable")

        rule_name = getattr(rule, "__name__", rule.__class__.__name__)
        rule_result = rule(**kwargs)

        if isinstance(rule_result, Mapping):
            normalized_result = dict(rule_result)
            normalized_result.setdefault("rule", rule_name)
        else:
            normalized_result = {
                "rule": rule_name,
                "result": rule_result,
            }

        results.append(normalized_result)

    return results
