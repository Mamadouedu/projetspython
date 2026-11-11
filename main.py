"""Point d'entrée CLI : pilote l'ensemble du pipeline de logs.

Lecture → Parse → Filter → Map → Match-case → Analytics → Rule engine → Affichage

Tout le pipeline est paresseux : les logs passent un par un, en un seul
passage, sans jamais être stockés dans une liste. La RAM reste constante
quelle que soit la taille du fichier.

Usage :
    python main.py --input data/sample_large.log --rules bruteforce,blacklist
    python main.py --input a.log b.log --limit 5 --threshold 3 --audit
"""

from __future__ import annotations

import argparse
from collections import defaultdict
from collections.abc import Callable, Iterable, Iterator
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

# Module 3 — Analytics (Dev C)
from src.analytics.bruteforce import detect_bruteforce
from src.analytics.sets_ops import ip_set_analysis

# Module 4 — Rule engine & audit (Dev C)
from src.engine.audit import audit_runtime_state
from src.engine.rule_engine import apply_security_rules

# Module 1 — Ingestion (Dev A)
from src.ingestion.log_generator import read_multiple_sources
from src.ingestion.parser import parse_line

# Module 2 — Pipeline fonctionnel (Dev B)
from src.pipeline.filters import drop_invalid, drop_invalid_requests
from src.pipeline.router import route_logs
from src.pipeline.transforms import normalize


# ---------------------------------------------------------------------------
# Statistiques accumulées pendant l'unique passage sur le flux
# ---------------------------------------------------------------------------
@dataclass
class PipelineStats:
    """Agrégats calculés au fil de l'eau (aucun log n'est stocké, sauf l'aperçu)."""

    total_lines: int = 0
    by_level: defaultdict[str, int] = field(default_factory=lambda: defaultdict(int))
    by_route: defaultdict[str, int] = field(default_factory=lambda: defaultdict(int))
    error_ips: set[str] = field(default_factory=set)
    active_ips: set[str] = field(default_factory=set)
    preview: list[dict[str, Any]] = field(default_factory=list)  # bornée à --limit

    @property
    def kept(self) -> int:
        """Nombre de logs valides arrivés au bout du pipeline."""
        return sum(self.by_level.values())


def count_lines(lines: Iterable[str], stats: PipelineStats) -> Iterator[str]:
    """Laisse passer les lignes brutes en les comptant (pour le % de rejet)."""
    for line in lines:
        stats.total_lines += 1
        yield line


def observe(
    logs: Iterable[dict[str, Any]], stats: PipelineStats, limit: int
) -> Iterator[dict[str, Any]]:
    """Générateur « espion » : met à jour les stats puis laisse passer le log.

    Permet de calculer plusieurs agrégats en UN SEUL passage, sans liste.
    """
    for log in logs:
        stats.by_level[log["level"]] += 1
        stats.by_route[log["route"]] += 1
        stats.active_ips.add(log["src_ip"])
        if log["level"] == "ERROR":
            stats.error_ips.add(log["src_ip"])
        if len(stats.preview) < limit:
            stats.preview.append(log)
        yield log


# ---------------------------------------------------------------------------
# Règles de sécurité (« si critère alors alerte »)
# Elles décident sur les résultats agrégés, pas sur le flux brut.
# (Place finale possible : src/engine/rules.py — à voir avec Baptiste.)
# ---------------------------------------------------------------------------
def check_bruteforce(bruteforce_ips: list[str], **_: Any) -> dict[str, Any]:
    """Alerte si des IP ont enchaîné trop d'échecs de login."""
    return {"alerte": bool(bruteforce_ips), "ips": bruteforce_ips}


def check_blacklist(active_ips: set[str], **_: Any) -> dict[str, Any]:
    """Alerte si des IP blacklistées sont actives."""
    suspectes = ip_set_analysis(active_ips)["blacklisted_active"]
    return {"alerte": bool(suspectes), "ips": sorted(suspectes)}


RULES: dict[str, Callable[..., dict[str, Any]]] = {
    "bruteforce": check_bruteforce,
    "blacklist": check_blacklist,
}


def parse_rules(value: str) -> list[Callable[..., dict[str, Any]]]:
    """Convertit "bruteforce,blacklist" en liste de fonctions (argparse type=)."""
    names = [n.strip() for n in value.split(",") if n.strip()]
    unknown = [n for n in names if n not in RULES]
    if unknown:
        raise argparse.ArgumentTypeError(
            f"règle(s) inconnue(s) : {', '.join(unknown)} "
            f"(disponibles : {', '.join(RULES)})"
        )
    return [RULES[n] for n in names]


# ---------------------------------------------------------------------------
# Affichage
# ---------------------------------------------------------------------------
def afficher_rapport(stats: PipelineStats, alertes: list[dict[str, Any]]) -> None:
    """Affiche l'aperçu, les statistiques et les alertes dans le terminal."""
    print(f"=== Aperçu des {len(stats.preview)} premiers logs ===")
    for log in stats.preview:
        print(
            f"[{log['route']:<12}] {log['timestamp']} {log['level']:<8} "
            f"{log['src_ip']:<15} {log['user_id']}"
        )

    dropped = stats.total_lines - stats.kept
    pct = 100 * dropped / max(stats.total_lines, 1)
    print(
        f"\n=== Volume ===\n  {stats.total_lines:,} lignes · {stats.kept:,} "
        f"valides · {dropped:,} rejetées ({pct:.1f} %)"
    )

    print("\n=== Par niveau ===")
    for level, n in sorted(stats.by_level.items()):
        print(f"  {level:<8} : {n:,}")

    print("\n=== Par format (match-case) ===")
    for route, n in sorted(stats.by_route.items(), key=lambda kv: -kv[1]):
        print(f"  {route:<12} : {n:,}")

    print(f"\n=== IP uniques ayant produit des ERROR : {len(stats.error_ips)} ===")

    print("\n=== Alertes de sécurité ===")
    for res in alertes:
        statut = "!! ALERTE" if res["alerte"] else "OK"  # ASCII : console Windows
        print(f"  {res['rule']:<18} {statut:<9} {res['ips'][:10]}")


# ---------------------------------------------------------------------------
# Orchestration
# ---------------------------------------------------------------------------
def build_arg_parser() -> argparse.ArgumentParser:
    """Définit les options de la ligne de commande."""
    p = argparse.ArgumentParser(description="Pipeline de logs sécurisé")
    p.add_argument(
        "--input",
        type=Path,
        nargs="+",
        required=True,
        help="Un ou plusieurs fichiers de logs (chaînés via yield from).",
    )
    p.add_argument(
        "--rules",
        type=parse_rules,
        default=list(RULES.values()),
        help=f"Règles à appliquer, séparées par des virgules "
        f"(défaut : {','.join(RULES)}).",
    )
    p.add_argument(
        "--threshold",
        type=int,
        default=5,
        help="Échecs de login consécutifs avant alerte brute force.",
    )
    p.add_argument(
        "--limit",
        type=int,
        default=10,
        help="Nombre de logs affichés en aperçu.",
    )
    p.add_argument(
        "--audit",
        action="store_true",
        help="Affiche le rapport d'introspection globals()/locals().",
    )
    return p


def main() -> None:
    """Enchaîne les 8 étapes du pipeline en un seul passage sur les fichiers."""
    args = build_arg_parser().parse_args()
    stats = PipelineStats()

    # Chaîne paresseuse : rien n'est lu tant que detect_bruteforce ne consomme pas.
    lignes = count_lines(read_multiple_sources(args.input), stats)  # 1. Lecture
    logs = map(parse_line, lignes)  # 2. Parse
    logs = drop_invalid(logs)  # 3. Filter
    logs = drop_invalid_requests(logs)
    logs = normalize(logs)  # 4. Map
    logs = route_logs(logs)  # 5. Match-case
    logs = observe(logs, stats, args.limit)  # 6. Analytics

    try:
        # Unique consommateur du flux → un seul passage sur le fichier.
        bruteforce_ips = detect_bruteforce(logs, threshold=args.threshold)
    except FileNotFoundError as exc:
        raise SystemExit(f"Fichier introuvable : {exc.filename}") from exc

    alertes = apply_security_rules(  # 7. Rule engine
        *args.rules,
        bruteforce_ips=bruteforce_ips,
        active_ips=stats.active_ips,
        threshold=args.threshold,
    )

    afficher_rapport(stats, alertes)  # 8. Affichage

    if args.audit:
        rapport = audit_runtime_state(tag="main")
        print(f"\n=== Audit ({rapport['tag']}) ===")
        print(f"  {len(rapport['globals_keys'])} noms globaux chargés")


if __name__ == "__main__":
    main()
