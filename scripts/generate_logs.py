"""Générateur de logs synthétiques pour le projet ING3.

Produit un fichier texte de logs varié, incluant :

- 4 niveaux de sévérité (INFO 70 %, WARNING 20 %, ERROR 8 %, CRITICAL 2 %).
- 200+ IPs sources distinctes (dont une dizaine dans la blacklist).
- 50+ `user_id` distincts.
- Payloads mixtes : JSON (~60 %), chaînes brutes (~25 %), tuples de
  connexion (~15 %).
- Timestamps répartis sur plusieurs jours.
- Rafales périodiques de 5 à 10 échecs de connexion consécutifs depuis
  une IP blacklistée (pour la détection brute-force du module 3).
- 5 à 10 % de **lignes sales** (consigne prof) à nettoyer : lignes vides,
  espaces parasites, timestamps mal formés, IPs invalides, champs
  manquants, JSON tronqué, niveaux inconnus, commentaires, séparateurs
  incohérents.

Usage :

    # Petit échantillon (pour développer, ~10 Mo)
    python scripts/generate_logs.py --out data/sample_small.log --gb 0.01

    # Dataset complet (prend plusieurs minutes, ~12 Go)
    python scripts/generate_logs.py --out data/sample_large.log --gb 12
"""
from __future__ import annotations

import argparse
import json
import random
from datetime import datetime, timedelta
from pathlib import Path
from typing import Callable

# --------------------------------------------------------------------------
# Configuration du contenu
# --------------------------------------------------------------------------

LEVELS: list[tuple[str, float]] = [
    ("INFO", 70.0),
    ("WARNING", 20.0),
    ("ERROR", 8.0),
    ("CRITICAL", 2.0),
]

UNKNOWN_LEVELS: list[str] = ["DEBUG", "UNKNOWN", "ERR0R", "trace", "warn"]

USERS: list[str] = [f"user_{i:03d}" for i in range(60)]
IPS: list[str] = [f"192.168.{a}.{b}" for a in range(1, 15) for b in range(1, 20)]
BLACKLIST_IPS: list[str] = IPS[:12]

PROTOCOLS: list[str] = ["TCP", "UDP", "HTTP", "HTTPS"]
ACTIONS: list[str] = ["login", "logout", "view", "edit", "delete", "upload", "download"]

DIRTY_RATIO: float = 0.07  # ~7 % de lignes sales
BRUTEFORCE_BURST_EVERY: int = 50_000
BRUTEFORCE_BURST_LEN: tuple[int, int] = (5, 10)

START_TIME: datetime = datetime(2026, 11, 1, 0, 0, 0)


# --------------------------------------------------------------------------
# Helpers de génération
# --------------------------------------------------------------------------


def weighted_level() -> str:
    """Retourne un niveau de sévérité pondéré selon LEVELS."""
    r = random.uniform(0, 100)
    acc = 0.0
    for level, weight in LEVELS:
        acc += weight
        if r < acc:
            return level
    return LEVELS[-1][0]


def clean_payload(level: str) -> str:
    """Payload bien formé (JSON / brut / tuple de connexion)."""
    kind = random.random()
    if kind < 0.60:
        status = "failed" if level in ("ERROR", "CRITICAL") else "ok"
        return json.dumps(
            {
                "action": random.choice(ACTIONS),
                "status": status,
                "bytes": random.randint(100, 50_000),
            }
        )
    if kind < 0.85:
        return f"raw event {random.randint(1000, 9999)}"
    # Tuple de connexion : (IP, Port, Protocole)
    ip = random.choice(IPS)
    port = random.randint(1024, 65535)
    proto = random.choice(PROTOCOLS)
    return f"({ip}, {port}, {proto})"


def clean_line(ts: datetime) -> str:
    """Ligne de log bien formée."""
    level = weighted_level()
    ip = random.choice(IPS)
    user = random.choice(USERS)
    payload = clean_payload(level)
    return f"{ts.isoformat()}Z | {level:8s} | {ip} | user={user} | {payload}"


def bruteforce_burst(ts: datetime) -> list[str]:
    """Rafale de 5 à 10 échecs consécutifs depuis une IP blacklistée."""
    ip = random.choice(BLACKLIST_IPS)
    user = random.choice(USERS)
    burst: list[str] = []
    length = random.randint(*BRUTEFORCE_BURST_LEN)
    for i in range(length):
        payload = json.dumps({"action": "login", "status": "failed"})
        burst.append(
            f"{(ts + timedelta(seconds=i)).isoformat()}Z | ERROR    "
            f"| {ip} | user={user} | {payload}"
        )
    return burst


# Variantes de lignes sales (consigne prof).
def _dirty_empty(ts: datetime) -> str:
    return ""


def _dirty_whitespace(ts: datetime) -> str:
    return "     "


def _dirty_leading_trailing(ts: datetime) -> str:
    return f"   {clean_line(ts)}   "


def _dirty_bad_timestamp(ts: datetime) -> str:
    return f"2026/11/04 18:32 | INFO | 192.168.1.42 | user=admin | {{}}"


def _dirty_bad_ip(ts: datetime) -> str:
    return (
        f"{ts.isoformat()}Z | INFO | 999.999.999.999 | user=admin | "
        f'{{"action": "login"}}'
    )


def _dirty_garbage_ip(ts: datetime) -> str:
    return f"{ts.isoformat()}Z | INFO | abc.def.ghi | user=admin | {{}}"


def _dirty_missing_user(ts: datetime) -> str:
    return f"{ts.isoformat()}Z | INFO | 192.168.1.42 | user= | {{}}"


def _dirty_missing_fields(ts: datetime) -> str:
    return f"{ts.isoformat()}Z | INFO | 192.168.1.42"


def _dirty_truncated_json(ts: datetime) -> str:
    return (
        f"{ts.isoformat()}Z | INFO | 192.168.1.42 | user=admin | "
        f'{{"action": "login"'
    )


def _dirty_bad_json(ts: datetime) -> str:
    return (
        f"{ts.isoformat()}Z | INFO | 192.168.1.42 | user=admin | "
        f"{{bad json, not valid}}"
    )


def _dirty_unknown_level(ts: datetime) -> str:
    return (
        f"{ts.isoformat()}Z | {random.choice(UNKNOWN_LEVELS)} | "
        f"192.168.1.42 | user=admin | {{}}"
    )


def _dirty_comment(ts: datetime) -> str:
    return f"# log technique ignoré n={random.randint(1, 9999)}"


def _dirty_glued_separators(ts: datetime) -> str:
    return f"{ts.isoformat()}Z|INFO|192.168.1.42|user=admin|{{}}"


DIRTY_VARIANTS: list[Callable[[datetime], str]] = [
    _dirty_empty,
    _dirty_whitespace,
    _dirty_leading_trailing,
    _dirty_bad_timestamp,
    _dirty_bad_ip,
    _dirty_garbage_ip,
    _dirty_missing_user,
    _dirty_missing_fields,
    _dirty_truncated_json,
    _dirty_bad_json,
    _dirty_unknown_level,
    _dirty_comment,
    _dirty_glued_separators,
]


def dirty_line(ts: datetime) -> str:
    """Ligne sale, variante choisie aléatoirement."""
    return random.choice(DIRTY_VARIANTS)(ts)


# --------------------------------------------------------------------------
# Boucle principale de génération
# --------------------------------------------------------------------------


def generate(path: Path, target_bytes: int) -> dict[str, int]:
    """Génère un fichier de logs jusqu'à atteindre `target_bytes`.

    Retourne un dict de statistiques (nb lignes totales, nb lignes sales,
    nb rafales brute-force) à titre informatif.
    """
    path.parent.mkdir(parents=True, exist_ok=True)

    stats = {"total": 0, "dirty": 0, "bursts": 0}
    written = 0
    i = 0

    with path.open("w", encoding="utf-8") as f:
        while written < target_bytes:
            # Timestamp pseudo-réparti (de 0.3s à 1.2s entre logs).
            ts = START_TIME + timedelta(seconds=i * random.uniform(0.3, 1.2))

            # Rafale brute-force périodique.
            if i > 0 and i % BRUTEFORCE_BURST_EVERY == 0:
                for line in bruteforce_burst(ts):
                    f.write(line + "\n")
                    written += len(line.encode("utf-8")) + 1
                    stats["total"] += 1
                stats["bursts"] += 1
                i += 1
                continue

            # Ligne sale ou propre.
            if random.random() < DIRTY_RATIO:
                line = dirty_line(ts)
                stats["dirty"] += 1
            else:
                line = clean_line(ts)

            f.write(line + "\n")
            written += len(line.encode("utf-8")) + 1
            stats["total"] += 1
            i += 1

    return stats


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Générateur de logs synthétiques (10-15 Go, varié, avec données sales)"
    )
    parser.add_argument(
        "--out",
        type=Path,
        default=Path("data/sample_small.log"),
        help="Chemin du fichier à écrire.",
    )
    parser.add_argument(
        "--gb",
        type=float,
        default=0.01,
        help="Taille cible en Go (défaut 0.01 = ~10 Mo).",
    )
    parser.add_argument(
        "--seed",
        type=int,
        default=42,
        help="Seed pour la reproductibilité.",
    )
    args = parser.parse_args()

    random.seed(args.seed)
    target = int(args.gb * 1024**3)

    print(f"[gen] écriture de ~{args.gb} Go dans {args.out} (seed={args.seed})...")
    stats = generate(args.out, target)
    size = args.out.stat().st_size
    pct_dirty = 100 * stats["dirty"] / max(stats["total"], 1)
    print(
        f"[gen] OK → {args.out} = {size / 1024**2:.2f} Mo "
        f"({size:,} octets, {stats['total']:,} lignes, "
        f"{stats['dirty']:,} sales ({pct_dirty:.1f} %), "
        f"{stats['bursts']} rafales brute-force)"
    )


if __name__ == "__main__":
    main()
