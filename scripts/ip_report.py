"""Rapport synthétique IP par IP : qui échoue, qui est bruteforce, qui est blacklist.

Le statut BRUTEFORCE affiché est le résultat **direct** de la fonction
``src.analytics.bruteforce.detect_bruteforce`` écrite par Dev C (Baptiste).
Le script lit le fichier en DEUX passes paresseuses sur le flux :

    Passe 1 : detect_bruteforce(logs) --> list[str] (les IPs détectées)
    Passe 2 : agrégation des compteurs par IP (total, logins, OK, FAIL, ERROR)

Ensuite, pour chaque IP du top N, on croise :
    - BRUTEFORCE si l'IP figure dans la sortie de detect_bruteforce
    - BLACKLIST si l'IP figure dans src.analytics.sets_ops.BLACKLIST (frozenset)

Usage :

    python scripts/ip_report.py --input data/sample_small.log --top 50
    python scripts/ip_report.py --input data/sample_large.log --top 50 --threshold 5
"""

from __future__ import annotations

import argparse
import sys
from collections import defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from src.analytics.bruteforce import detect_bruteforce
from src.analytics.sets_ops import BLACKLIST
from src.ingestion.log_generator import read_log_file
from src.ingestion.parser import parse_line
from src.pipeline.filters import drop_invalid


def iter_valid_logs(path: Path):
    """Un flux paresseux de logs valides (generator)."""
    raw = (parse_line(line) for line in read_log_file(path))
    yield from drop_invalid(raw)


def build_ip_stats(path: Path) -> dict[str, dict[str, int]]:
    """Agrège les compteurs par IP en UNE passe paresseuse."""
    stats: dict[str, dict[str, int]] = defaultdict(
        lambda: {"logins": 0, "login_ok": 0, "login_fail": 0, "errors": 0, "total": 0}
    )

    for log in iter_valid_logs(path):
        ip = log["src_ip"]
        s = stats[ip]
        s["total"] += 1
        if log["level"] == "ERROR":
            s["errors"] += 1

        payload = log["payload"]
        if isinstance(payload, dict) and payload.get("action") == "login":
            s["logins"] += 1
            status = str(payload.get("status", "")).lower()
            if status in {"failed", "failure"}:
                s["login_fail"] += 1
            elif status == "ok":
                s["login_ok"] += 1

    return dict(stats)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", required=True, help="Fichier de logs à analyser")
    parser.add_argument("--top", type=int, default=50, help="Nombre d'IPs à afficher")
    parser.add_argument(
        "--threshold",
        type=int,
        default=5,
        help="Seuil passé à detect_bruteforce (défaut : 5)",
    )
    parser.add_argument(
        "--sort",
        choices=("login_fail", "total", "errors"),
        default="login_fail",
        help="Critère de tri (défaut : login_fail)",
    )
    args = parser.parse_args()

    path = Path(args.input)
    if not path.exists():
        raise SystemExit(f"Fichier introuvable : {path}")

    # ---------------------------------------------------------------------
    # PASSE 1 : appel direct à la fonction de Baptiste.
    # L'ensemble renvoyé est la "vérité" officielle du statut BRUTEFORCE.
    # ---------------------------------------------------------------------
    print(f"[passe 1/2] detect_bruteforce(logs, threshold={args.threshold}) ...")
    bruteforce_ips: set[str] = set(
        detect_bruteforce(iter_valid_logs(path), threshold=args.threshold)
    )
    print(f"           -> {len(bruteforce_ips)} IPs détectées par Dev C.\n")

    # ---------------------------------------------------------------------
    # PASSE 2 : agrégation des compteurs pour affichage.
    # ---------------------------------------------------------------------
    print("[passe 2/2] Agrégation des compteurs par IP ...")
    stats = build_ip_stats(path)
    print(f"           -> {len(stats)} IPs uniques dans le fichier.\n")

    ordered = sorted(stats.items(), key=lambda kv: kv[1][args.sort], reverse=True)
    top = ordered[: args.top]

    print(
        f"Top {args.top} IPs triées par '{args.sort}' "
        f"(seuil detect_bruteforce : {args.threshold}) :\n"
    )
    header = (
        f"{'#':>3}  {'IP':<18}  {'Total':>7}  {'Logins':>7}  "
        f"{'OK':>5}  {'FAIL':>5}  {'ERROR':>6}  {'Statut':<24}"
    )
    print(header)
    print("-" * len(header))

    bf_in_top: set[str] = set()
    bl_in_top: set[str] = set()
    for rank, (ip, s) in enumerate(top, 1):
        tags = []
        if ip in bruteforce_ips:  # <-- décision : fonction de Baptiste
            tags.append("BRUTEFORCE")
            bf_in_top.add(ip)
        if ip in BLACKLIST:  # <-- décision : frozenset de Baptiste
            tags.append("BLACKLIST")
            bl_in_top.add(ip)
        if not tags:
            tags.append("OK")
        statut = " + ".join(tags)
        print(
            f"{rank:>3}  {ip:<18}  {s['total']:>7}  {s['logins']:>7}  "
            f"{s['login_ok']:>5}  {s['login_fail']:>5}  {s['errors']:>6}  {statut:<24}"
        )

    only_bf = len(bf_in_top - bl_in_top)
    only_bl = len(bl_in_top - bf_in_top)
    both = len(bf_in_top & bl_in_top)
    ok_count = args.top - len(bf_in_top | bl_in_top)

    print()
    print(f"=== Synthèse sur le top {args.top} (décisions de Dev C) ===")
    print(f"  BRUTEFORCE seulement   (detect_bruteforce) : {only_bf}")
    print(f"  BLACKLIST seulement    (sets_ops.BLACKLIST) : {only_bl}")
    print(f"  BRUTEFORCE + BLACKLIST (les deux)           : {both}")
    print(f"  OK (ni l'un ni l'autre)                     : {ok_count}")
    print()
    print("=== Total sur le fichier complet ===")
    print(f"  IPs détectées par detect_bruteforce : {len(bruteforce_ips)}")
    print(f"  IPs dans BLACKLIST (frozenset)      : {len(BLACKLIST)}")
    print()
    print("Note : detect_bruteforce compte les échecs CONSÉCUTIFS (un succès remet")
    print("       le compteur à 0). La colonne FAIL affichée est le TOTAL des échecs,")
    print(
        "       plus laxiste — donc FAIL >= threshold n'entraîne pas forcément BRUTEFORCE."
    )


if __name__ == "__main__":
    main()
