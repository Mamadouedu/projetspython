"""Démonstration interactive des fonctions-clés du pipeline.

À lancer depuis la racine du projet :

    python scripts/demo_functions.py
    python scripts/demo_functions.py --input data/sample_small.log

Affiche pour chaque fonction importante :
    - un cartouche avec son nom et son module
    - un exemple d'ENTRÉE
    - sa SORTIE réelle sur le dataset

Permet de prouver en soutenance que chaque fonction "parle" (produit des données
utiles), au-delà des 40 tests pytest qui ne font que vérifier qu'elles existent
et renvoient le bon type.
"""

from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from itertools import islice
from pathlib import Path

# Rendre le package `src` importable quand on lance ce script depuis `scripts/`.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from src.analytics.bruteforce import detect_bruteforce
from src.analytics.counters import count_by_category
from src.analytics.sets_ops import ip_set_analysis, unique_error_ips
from src.engine.audit import audit_runtime_state
from src.engine.rule_engine import apply_security_rules
from src.ingestion.log_generator import read_log_file
from src.ingestion.parser import parse_line
from src.pipeline.filters import (
    by_ip,
    by_level,
    drop_invalid,
    drop_invalid_requests,
    failed_logins,
    is_valid_request,
)
from src.pipeline.router import add_route, get_route, route_logs
from src.pipeline.transforms import clean_log, format_timestamp, normalize


def banner(title: str) -> None:
    print()
    print("=" * 78)
    print(f"  {title}")
    print("=" * 78)


def show(label: str, value: object, limit: int = 300) -> None:
    text = repr(value) if not isinstance(value, str) else value
    if len(text) > limit:
        text = text[:limit] + " ... (tronqué)"
    print(f"  {label:<8} {text}")


def demo(path: Path) -> None:
    # ------------------------------------------------------------------
    # 1. Ingestion : read_log_file (generator) + parse_line
    # ------------------------------------------------------------------
    banner("1. src.ingestion.log_generator.read_log_file  (yield, paresseux)")
    gen = read_log_file(path)
    show("TYPE", type(gen).__name__)  # generator
    first_lines = list(islice(gen, 3))
    for i, line in enumerate(first_lines, 1):
        show(f"L{i}", line.rstrip("\n"))

    banner("2. src.ingestion.parser.parse_line  (ligne brute -> LogEntry|None)")
    for raw in first_lines[:2]:
        show("IN", raw.rstrip("\n"))
        show("OUT", parse_line(raw))
    show("IN", "# ligne commentaire")
    show("OUT", parse_line("# ligne commentaire"))

    # ------------------------------------------------------------------
    # 3. Filtres (filter + lambda, paresseux)
    # ------------------------------------------------------------------
    banner("3. src.pipeline.filters  (filter + lambda, paresseux)")
    logs = (parse_line(l) for l in read_log_file(path))
    valid = list(drop_invalid(logs))
    show("drop_invalid", f"{len(valid)} logs valides sur le dataset")

    sample_log = valid[0]
    show("is_valid_request IN", sample_log)
    show("is_valid_request OUT", is_valid_request(sample_log))

    error_logs = list(islice(by_level(iter(valid), "ERROR"), 3))
    show("by_level('ERROR') OUT", f"{len(error_logs)} premiers logs ERROR")
    for log in error_logs:
        show("  log", log)

    if error_logs:
        ip = error_logs[0]["src_ip"]
        same_ip = list(islice(by_ip(iter(valid), ip), 5))
        show(f"by_ip({ip!r}) OUT", f"{len(same_ip)} logs pour cette IP")

    cleaned = list(drop_invalid_requests(iter(valid)))
    show("drop_invalid_requests", f"{len(cleaned)} logs après filtrage JSON cassé")

    fails = list(failed_logins(iter(valid)))
    show("failed_logins OUT", f"{len(fails)} échecs de login au total")

    # ------------------------------------------------------------------
    # 4. Transforms (map + clean)
    # ------------------------------------------------------------------
    banner("4. src.pipeline.transforms  (map, normalisation)")
    show("format_timestamp IN", "2026-11-04T18:32:15.123456Z")
    show("format_timestamp OUT", format_timestamp("2026-11-04T18:32:15.123456Z"))
    show("clean_log IN", sample_log)
    show("clean_log OUT", clean_log(sample_log))
    normalized = list(islice(normalize(iter(valid)), 2))
    for i, log in enumerate(normalized, 1):
        show(f"normalize L{i}", log)

    # ------------------------------------------------------------------
    # 5. Router (match-case 3 branches)
    # ------------------------------------------------------------------
    banner("5. src.pipeline.router  (match-case, 3 branches)")
    for log in valid[:5]:
        show("payload", log["payload"])
        show("get_route", get_route(log))
        print()
    routed = list(islice(route_logs(iter(valid)), 3))
    show("route_logs OUT", f"{len(routed)} premiers logs avec champ 'route'")
    for log in routed:
        show("  routed", {"route": log.get("route"), "level": log.get("level")})

    counts_route = Counter(get_route(l) for l in valid)
    show("Répartition routes", dict(counts_route))

    # ------------------------------------------------------------------
    # 6. Analytics (sets, counters, bruteforce)
    # ------------------------------------------------------------------
    banner("6. src.analytics  (set / defaultdict / detect_bruteforce)")
    err_ips = unique_error_ips(iter(valid))
    show("unique_error_ips TYPE", type(err_ips).__name__)
    show("unique_error_ips OUT", f"{len(err_ips)} IPs uniques en ERROR")
    show("  échantillon", list(err_ips)[:5])

    analysis = ip_set_analysis(err_ips)
    show("ip_set_analysis clés", list(analysis.keys()))
    for key, value in analysis.items():
        show(f"  {key}", f"{len(value)} IPs")

    counts = count_by_category(iter(valid), category="level")
    show("count_by_category('level')", dict(counts))

    detected = detect_bruteforce(iter(valid), threshold=3)
    show("detect_bruteforce threshold=3", detected)

    # ------------------------------------------------------------------
    # 7. Rule engine (*args, **kwargs, functions-as-values)
    # ------------------------------------------------------------------
    banner("7. src.engine.rule_engine.apply_security_rules  (*args, **kwargs)")

    def check_bruteforce(bruteforce_ips: list[str], **_: object) -> dict[str, object]:
        return {
            "rule": "bruteforce",
            "count": len(bruteforce_ips),
            "ips": bruteforce_ips,
        }

    def check_blacklist(active_ips: set[str], **_: object) -> dict[str, object]:
        blacklist = frozenset({"10.0.0.5", "203.0.113.7"})
        hits = active_ips & blacklist
        return {"rule": "blacklist", "count": len(hits), "ips": sorted(hits)}

    results = apply_security_rules(
        check_bruteforce,
        check_blacklist,
        bruteforce_ips=detected,
        active_ips=err_ips,
    )
    show("apply_security_rules OUT", json.dumps(results, ensure_ascii=False, indent=2))

    # ------------------------------------------------------------------
    # 8. Introspection (globals / locals)
    # ------------------------------------------------------------------
    banner("8. src.engine.audit.audit_runtime_state  (globals/locals)")
    state = audit_runtime_state(tag="demo")
    show("tag", state["tag"])
    show("globals_keys", f"{len(state['globals_keys'])} noms globaux")
    show("  échantillon", state["globals_keys"][:8])
    show("locals_snapshot", f"{len(state['locals_snapshot'])} variables locales")

    # ------------------------------------------------------------------
    # 9. add_route (pour montrer qu'on enrichit sans muter)
    # ------------------------------------------------------------------
    banner("9. src.pipeline.router.add_route  (enrichit sans muter l'entrée)")
    show("IN", sample_log)
    show("OUT", add_route(sample_log))
    show("IN inchangé ?", "route" not in sample_log)

    print()
    print("=" * 78)
    print("  FIN — chaque fonction a produit une sortie réelle sur le dataset.")
    print("=" * 78)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--input",
        default="data/sample_small.log",
        help="Fichier de logs à utiliser (défaut : data/sample_small.log)",
    )
    args = parser.parse_args()
    path = Path(args.input)
    if not path.exists():
        raise SystemExit(f"Fichier introuvable : {path}")
    demo(path)


if __name__ == "__main__":
    main()
