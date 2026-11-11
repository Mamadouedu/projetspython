"""Rapport synthétique des fonctions analytics + engine (Dev C / Baptiste).

Fait parler les 4 fonctions-clés sur le dataset réel, comme ``ip_report.py``
le fait pour ``detect_bruteforce`` :

    1. count_by_category       (analytics.counters)
    2. unique_error_ips        (analytics.sets_ops)
    3. audit_runtime_state     (engine.audit)
    4. apply_security_rules    (engine.rule_engine)

Chaque section montre un cartouche avec l'entrée envoyée à la fonction et
sa sortie réelle. Utile pour la soutenance : prouver que chaque fonction
produit des données, au-delà des 19 tests pytest qui vérifient juste la
forme du retour.

Usage :

    python scripts/analytics_report.py --input data/sample_small.log
    python scripts/analytics_report.py --input data/sample_large.log --top 20
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from src.analytics.bruteforce import detect_bruteforce
from src.analytics.counters import count_by_category
from src.analytics.sets_ops import BLACKLIST, ip_set_analysis, unique_error_ips
from src.engine.audit import audit_runtime_state
from src.engine.rule_engine import apply_security_rules
from src.ingestion.log_generator import read_log_file
from src.ingestion.parser import parse_line
from src.pipeline.filters import drop_invalid


def banner(title: str) -> None:
    print()
    print("=" * 78)
    print(f"  {title}")
    print("=" * 78)


def line(label: str, value: object, limit: int = 300) -> None:
    text = repr(value) if not isinstance(value, str) else value
    if len(text) > limit:
        text = text[:limit] + " ... (tronqué)"
    print(f"  {label:<24} {text}")


def iter_valid_logs(path: Path):
    raw = (parse_line(l) for l in read_log_file(path))
    yield from drop_invalid(raw)


def demo(path: Path, top: int) -> None:
    # ------------------------------------------------------------------
    # 1. count_by_category  (defaultdict(int), paresseux)
    # ------------------------------------------------------------------
    banner("1. src.analytics.counters.count_by_category")
    line(
        "Signature",
        "count_by_category(logs, category='level') -> defaultdict[str, int]",
    )

    print("\n  --- Comptage par niveau de sévérité ---")
    counts_level = count_by_category(iter_valid_logs(path), category="level")
    total = sum(counts_level.values())
    line("TYPE de retour", type(counts_level).__name__)
    line("Nombre de clés", len(counts_level))
    line("Total de logs comptés", total)
    for level in sorted(counts_level, key=counts_level.get, reverse=True):
        n = counts_level[level]
        pct = n / total * 100 if total else 0
        print(f"      {level:<10} {n:>10,}  ({pct:5.2f} %)")

    print("\n  --- Comptage par utilisateur (top 10) ---")
    counts_user = count_by_category(iter_valid_logs(path), category="user_id")
    line("Nombre d'utilisateurs uniques", len(counts_user))
    top_users = sorted(counts_user.items(), key=lambda kv: kv[1], reverse=True)[:10]
    for user, n in top_users:
        print(f"      {user:<15} {n:>10,}")

    # ------------------------------------------------------------------
    # 2. unique_error_ips  (set[str])
    # ------------------------------------------------------------------
    banner("2. src.analytics.sets_ops.unique_error_ips")
    line("Signature", "unique_error_ips(logs) -> set[str]")

    err_ips = unique_error_ips(iter_valid_logs(path))
    line("TYPE de retour", type(err_ips).__name__)
    line("Nombre d'IPs uniques en ERROR", len(err_ips))
    line("Échantillon (10 premières)", list(err_ips)[:10])

    print("\n  --- Croisement avec BLACKLIST (4 opérateurs de set) ---")
    analysis = ip_set_analysis(err_ips)
    line(
        "blacklisted_active (&)",
        f"{len(analysis['blacklisted_active'])} IPs → {sorted(analysis['blacklisted_active'])}",
    )
    line("all_known          (|)", f"{len(analysis['all_known'])} IPs")
    line("clean_active       (-)", f"{len(analysis['clean_active'])} IPs")
    line("exclusives         (^)", f"{len(analysis['exclusives'])} IPs")

    # ------------------------------------------------------------------
    # 3. audit_runtime_state  (globals + locals)
    # ------------------------------------------------------------------
    banner("3. src.engine.audit.audit_runtime_state")
    line("Signature", "audit_runtime_state(tag='audit') -> dict")

    print("\n  --- Appel 1 : tag par défaut ---")
    state_1 = audit_runtime_state()
    line("TYPE de retour", type(state_1).__name__)
    line("Clés retournées", sorted(state_1.keys()))
    line("tag", state_1["tag"])
    line("globals_keys (nb)", len(state_1["globals_keys"]))
    line("globals échantillon", state_1["globals_keys"][:8])
    line("locals_snapshot", state_1["locals_snapshot"])

    print("\n  --- Appel 2 : tag='fin_de_run' ---")
    state_2 = audit_runtime_state("fin_de_run")
    line("tag", state_2["tag"])
    line("locals_snapshot", state_2["locals_snapshot"])

    # ------------------------------------------------------------------
    # 4. apply_security_rules  (*args, **kwargs, first-class functions)
    # ------------------------------------------------------------------
    banner("4. src.engine.rule_engine.apply_security_rules")
    line("Signature", "apply_security_rules(*rules, **kwargs) -> list[dict]")

    # On définit 3 règles comme SIMPLES FONCTIONS : elles sont passées
    # en *args et reçoivent les mêmes **kwargs (démo : fonctions = valeurs).
    def check_bruteforce(bruteforce_ips, **_):
        return {
            "rule": "check_bruteforce",
            "count": len(bruteforce_ips),
            "ips": sorted(bruteforce_ips)[:10],
        }

    def check_blacklist(active_ips, **_):
        hits = sorted(active_ips & BLACKLIST)
        return {"rule": "check_blacklist", "count": len(hits), "ips": hits}

    def rule_global_counts(counts_level, **_):
        total = sum(counts_level.values())
        critical_ratio = counts_level.get("CRITICAL", 0) / total if total else 0
        return {
            "rule": "rule_global_counts",
            "total_logs": total,
            "critical_ratio_pct": round(critical_ratio * 100, 4),
        }

    print("\n  --- Préparation des données pour les règles ---")
    bf_ips = set(detect_bruteforce(iter_valid_logs(path), threshold=5))
    line("bruteforce_ips (detect_bruteforce)", f"{len(bf_ips)} IPs")
    line("active_ips (unique_error_ips)", f"{len(err_ips)} IPs")
    line("counts_level (count_by_category)", dict(counts_level))

    print("\n  --- Appel apply_security_rules(3 règles, **kwargs) ---")
    results = apply_security_rules(
        check_bruteforce,
        check_blacklist,
        rule_global_counts,
        bruteforce_ips=bf_ips,
        active_ips=err_ips,
        counts_level=counts_level,
    )
    line("TYPE de retour", type(results).__name__)
    line("Nombre de règles appliquées", len(results))
    print("  Sortie formatée :")
    print(json.dumps(results, indent=4, ensure_ascii=False, default=list))

    # ------------------------------------------------------------------
    print()
    print("=" * 78)
    print("  FIN — les 4 fonctions ont produit une sortie réelle sur le dataset.")
    print("=" * 78)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--input",
        default="data/sample_small.log",
        help="Fichier de logs (défaut : data/sample_small.log)",
    )
    parser.add_argument("--top", type=int, default=10, help="Nombre d'éléments par top")
    args = parser.parse_args()
    path = Path(args.input)
    if not path.exists():
        raise SystemExit(f"Fichier introuvable : {path}")
    demo(path, args.top)


if __name__ == "__main__":
    main()
