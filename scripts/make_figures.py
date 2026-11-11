"""Produit les figures 3, 4 et 5 du rapport depuis le dataset réel.

Respecte l'esprit du projet : UNE SEULE passe paresseuse sur le fichier via
générateurs. Les compteurs s'accumulent au fil de l'eau, sans jamais charger
le fichier en mémoire.

- Figure 3 : camembert de la répartition des niveaux de sévérité.
- Figure 4 : top 10 des IPs ayant produit des logs ERROR.
- Figure 5 : top 10 des IPs ayant le plus de tentatives de login échouées
             (candidats à l'alerte bruteforce).

Usage :

    python scripts/make_figures.py --input data/sample_large.log --out figures/
    python scripts/make_figures.py --input data/sample_small.log --out figures/
"""
from __future__ import annotations

import argparse
import json
import sys
import time
from collections import Counter
from collections.abc import Iterator
from pathlib import Path
from typing import Any

# Permet d'importer src.* quand on exécute depuis scripts/
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import matplotlib

matplotlib.use("Agg")  # backend sans GUI
import matplotlib.pyplot as plt  # noqa: E402

from src.ingestion.log_generator import read_log_file  # noqa: E402
from src.ingestion.parser import parse_line  # noqa: E402
from src.pipeline.filters import drop_invalid  # noqa: E402
from src.pipeline.transforms import normalize  # noqa: E402


LEVEL_COLORS = {
    "INFO": "#4C9AFF",
    "WARNING": "#FFAB00",
    "ERROR": "#FF5630",
    "CRITICAL": "#8B0000",
}


def accumulate(logs: Iterator[dict[str, Any]]) -> dict[str, Any]:
    """Parcourt le flux UNE SEULE FOIS et accumule les compteurs."""
    by_level: Counter[str] = Counter()
    by_ip_error: Counter[str] = Counter()
    failed_login_by_ip: Counter[str] = Counter()
    total = 0

    for log in logs:
        total += 1
        level = log["level"]
        src_ip = log["src_ip"]
        by_level[level] += 1

        if level == "ERROR":
            by_ip_error[src_ip] += 1

        # Tentative de login échouée ?
        payload = log["payload"]
        if isinstance(payload, dict):
            action = str(payload.get("action", "")).strip().lower()
            status = str(payload.get("status", "")).strip().lower()
            if action == "login" and status in {"failed", "failure"}:
                failed_login_by_ip[src_ip] += 1

    return {
        "total": total,
        "by_level": dict(by_level),
        "top_error_ips": by_ip_error.most_common(10),
        "top_failed_login_ips": failed_login_by_ip.most_common(10),
    }


def figure_3_levels(stats: dict[str, Any], out: Path) -> None:
    """Camembert de la répartition des niveaux."""
    by_level = stats["by_level"]
    ordered = ["INFO", "WARNING", "ERROR", "CRITICAL"]
    labels = [lv for lv in ordered if lv in by_level]
    sizes = [by_level[lv] for lv in labels]
    colors = [LEVEL_COLORS[lv] for lv in labels]

    fig, ax = plt.subplots(figsize=(7, 6))
    wedges, _, autotexts = ax.pie(
        sizes,
        labels=labels,
        colors=colors,
        autopct=lambda p: f"{p:.1f}%\n({int(p * sum(sizes) / 100):,})",
        startangle=90,
        textprops={"fontsize": 11},
    )
    for t in autotexts:
        t.set_color("white")
        t.set_fontweight("bold")
    ax.set_title(
        f"Figure 3 — Répartition des niveaux de sévérité\n"
        f"({stats['total']:,} logs valides)",
        fontsize=13,
    )
    ax.axis("equal")
    fig.tight_layout()
    fig.savefig(out, dpi=150, bbox_inches="tight")
    plt.close(fig)
    print(f"[ok] {out}")


def figure_4_top_error_ips(stats: dict[str, Any], out: Path) -> None:
    """Top 10 des IPs en ERROR."""
    top = stats["top_error_ips"]
    if not top:
        print(f"[skip] {out} — aucune IP en ERROR")
        return
    ips = [ip for ip, _ in top]
    counts = [c for _, c in top]

    fig, ax = plt.subplots(figsize=(10, 6))
    bars = ax.barh(ips[::-1], counts[::-1], color="#FF5630")
    ax.set_xlabel("Nombre de logs ERROR", fontsize=11)
    ax.set_ylabel("Adresse IP source", fontsize=11)
    ax.set_title("Figure 4 — Top 10 des IPs générant des erreurs", fontsize=13)
    ax.grid(axis="x", linestyle="--", alpha=0.3)

    max_val = max(counts)
    for bar, val in zip(bars, counts[::-1]):
        ax.text(
            val + max_val * 0.01,
            bar.get_y() + bar.get_height() / 2,
            f"{val:,}",
            va="center",
            fontsize=10,
        )
    fig.tight_layout()
    fig.savefig(out, dpi=150, bbox_inches="tight")
    plt.close(fig)
    print(f"[ok] {out}")


def figure_5_bruteforce(stats: dict[str, Any], out: Path) -> None:
    """Top 10 des IPs avec le plus de logins échoués (candidats bruteforce)."""
    top = stats["top_failed_login_ips"]
    if not top:
        print(f"[skip] {out} — aucun login échoué")
        return
    ips = [ip for ip, _ in top]
    counts = [c for _, c in top]

    fig, ax = plt.subplots(figsize=(10, 6))
    bars = ax.barh(ips[::-1], counts[::-1], color="#8B0000")
    ax.set_xlabel("Tentatives de login échouées", fontsize=11)
    ax.set_ylabel("Adresse IP source", fontsize=11)
    ax.set_title(
        "Figure 5 — Top 10 des IPs avec tentatives bruteforce\n"
        "(candidats à l'alerte, seuil = 5 échecs consécutifs)",
        fontsize=13,
    )
    ax.grid(axis="x", linestyle="--", alpha=0.3)

    max_val = max(counts)
    for bar, val in zip(bars, counts[::-1]):
        ax.text(
            val + max_val * 0.01,
            bar.get_y() + bar.get_height() / 2,
            f"{val:,}",
            va="center",
            fontsize=10,
        )
    fig.tight_layout()
    fig.savefig(out, dpi=150, bbox_inches="tight")
    plt.close(fig)
    print(f"[ok] {out}")


def main() -> None:
    p = argparse.ArgumentParser(description="Génère les figures 3, 4, 5 du rapport")
    p.add_argument("--input", type=Path, required=True, help="Fichier de logs (.log)")
    p.add_argument(
        "--out",
        type=Path,
        default=Path("figures"),
        help="Dossier de sortie des PNGs (défaut : figures/)",
    )
    args = p.parse_args()

    if not args.input.exists():
        raise SystemExit(f"Fichier introuvable : {args.input}")
    args.out.mkdir(parents=True, exist_ok=True)

    # Chaîne paresseuse : UNE SEULE passe sur le fichier.
    lignes = read_log_file(args.input)
    logs = map(parse_line, lignes)
    logs = drop_invalid(logs)
    logs = normalize(logs)

    size_mb = args.input.stat().st_size / (1024 * 1024)
    print(f"Analyse de {args.input} ({size_mb:,.1f} Mo)...")
    t0 = time.perf_counter()
    stats = accumulate(logs)
    elapsed = time.perf_counter() - t0
    print(f"=> {stats['total']:,} logs valides parcourus en {elapsed:.1f} s")

    # Sauvegarde des stats pour traçabilité / reproduction
    stats_json = args.out / "stats.json"
    stats_json.write_text(
        json.dumps(stats, ensure_ascii=False, indent=2), encoding="utf-8"
    )
    print(f"[ok] {stats_json}")

    figure_3_levels(stats, args.out / "figure_3_levels.png")
    figure_4_top_error_ips(stats, args.out / "figure_4_top_error_ips.png")
    figure_5_bruteforce(stats, args.out / "figure_5_bruteforce.png")

    print(f"\nTerminé en {time.perf_counter() - t0:.1f} s.")


if __name__ == "__main__":
    main()
