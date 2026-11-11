"""Rapport synthétique IP par IP : qui échoue, qui est bruteforce, qui est blacklist.

Montre pourquoi `check_bruteforce` peut sortir une liste vide : les IPs analysées
peuvent être sous le seuil. Ici on voit TOUTES les IPs qui tentent des logins
(ou qu'on choisit de lister) avec leur nombre d'échecs et leur statut.

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

from src.analytics.sets_ops import BLACKLIST
from src.ingestion.log_generator import read_log_file
from src.ingestion.parser import parse_line
from src.pipeline.filters import drop_invalid


def build_ip_stats(path: Path) -> dict[str, dict[str, int]]:
    """Agrège les compteurs par IP en UNE passe paresseuse.

    Retourne : {ip: {"logins": n, "login_ok": n, "login_fail": n, "errors": n}}
    """
    stats: dict[str, dict[str, int]] = defaultdict(
        lambda: {"logins": 0, "login_ok": 0, "login_fail": 0, "errors": 0, "total": 0}
    )

    logs = (parse_line(line) for line in read_log_file(path))
    for log in drop_invalid(logs):
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
        "--threshold", type=int, default=5, help="Seuil bruteforce (défaut : 5)"
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

    print(f"Lecture de {path} ...")
    stats = build_ip_stats(path)
    print(f"{len(stats)} IPs uniques trouvées.\n")

    # Tri descendant sur le critère demandé
    ordered = sorted(stats.items(), key=lambda kv: kv[1][args.sort], reverse=True)
    top = ordered[: args.top]

    # En-tête
    print(
        f"Top {args.top} IPs triées par '{args.sort}' (seuil bruteforce : {args.threshold}) :\n"
    )
    header = f"{'#':>3}  {'IP':<18}  {'Total':>7}  {'Logins':>7}  {'OK':>5}  {'FAIL':>5}  {'ERROR':>6}  {'Statut':<20}"
    print(header)
    print("-" * len(header))

    bruteforce_ips: set[str] = set()
    blacklist_ips: set[str] = set()
    for rank, (ip, s) in enumerate(top, 1):
        tags = []
        if s["login_fail"] >= args.threshold:
            tags.append("BRUTEFORCE")
            bruteforce_ips.add(ip)
        if ip in BLACKLIST:
            tags.append("BLACKLIST")
            blacklist_ips.add(ip)
        if not tags:
            tags.append("OK")
        statut = " + ".join(tags)
        print(
            f"{rank:>3}  {ip:<18}  {s['total']:>7}  {s['logins']:>7}  "
            f"{s['login_ok']:>5}  {s['login_fail']:>5}  {s['errors']:>6}  {statut:<20}"
        )

    only_bf = len(bruteforce_ips - blacklist_ips)
    only_bl = len(blacklist_ips - bruteforce_ips)
    both = len(bruteforce_ips & blacklist_ips)
    ok = args.top - len(bruteforce_ips | blacklist_ips)
    print()
    print(f"=== Synthese sur le top {args.top} ===")
    print(f"  BRUTEFORCE seulement (login_fail >= {args.threshold}) : {only_bf}")
    print(f"  BLACKLIST seulement                                 : {only_bl}")
    print(f"  BRUTEFORCE + BLACKLIST (les deux)                   : {both}")
    print(f"  OK (ni l'un ni l'autre)                             : {ok}")
    print()
    print("Note : login_fail = total des echecs de login pour cette IP.")
    print("       detect_bruteforce (analytics) utilise les echecs CONSECUTIFS,")
    print("       qui remettent le compteur a zero sur un succes : plus severe.")


if __name__ == "__main__":
    main()
