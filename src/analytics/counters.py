"""Comptage des événements présents dans les logs."""

from collections import defaultdict
from collections.abc import Iterable, Mapping
from typing import Any


def count_by_category(
    logs: Iterable[Mapping[str, Any]], category: str = "level"
) -> defaultdict[str, int]:
    """Compte les logs par catégorie (par défaut, leur niveau de sévérité).

    Pour compter par utilisateur, appeler par exemple
    ``count_by_category(logs, category="user_id")``.
    Les logs qui ne possèdent pas la catégorie demandée sont ignorés.
    """
    counts: defaultdict[str, int] = defaultdict(int)

    for log in logs:
        if not isinstance(log, Mapping):
            continue

        value = log.get(category)
        if value is None:
            continue

        key = str(value).strip()
        if not key:
            continue

        counts[key] += 1

    return counts
