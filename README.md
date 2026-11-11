# Projet Python ING3 — Pipeline de logs sécurisé

## Installation

```powershell
python -m venv venv
.\venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

## Génération du dataset

Le fichier 10-15 Go n'est **pas** commité ; chacun le régénère via le script versionné :

```powershell
# Petit échantillon pour tests rapides (~10 Mo)
python scripts/generate_logs.py --out data/sample_small.log --gb 0.01

# Dataset complet (10-15 Go, plusieurs minutes, reproductible avec --seed)
python scripts/generate_logs.py --out data/sample_large.log --gb 12 --seed 42
```

## Lancement du pipeline

```powershell
# Exécution simple
python main.py --input data/sample_small.log --limit 10

# Avec règles de sécurité et audit d'introspection
python main.py --input data/sample_large.log --rules bruteforce,blacklist --audit

# Chaînage de plusieurs sources via yield from
python main.py --input a.log b.log --threshold 5 --limit 5
```

Options :
- `--input` : un ou plusieurs fichiers de logs (chaînés avec `yield from`)
- `--rules` : règles à appliquer (`bruteforce`, `blacklist`, ou les deux)
- `--threshold` : échecs de login consécutifs avant alerte bruteforce (défaut : 5)
- `--limit` : nombre de logs affichés en aperçu (défaut : 10)
- `--audit` : affiche le rapport d'introspection `globals()` / `locals()`

## Tests

```powershell
pytest tests/ -v
```

**53 tests** répartis en : 16 ingestion (`test_ingestion.py`) + 18 pipeline (`test_pipeline.py`) + 19 analytics/engine (`test_dev_c.py`).

## Mémoire (preuve non-saturation RAM)

```powershell
# Mode read-only (lecture seule, rapide)
python scripts/bench_memory.py --input data/sample_large.log --read-only

# Mode complet (lecture + parsing)
python scripts/bench_memory.py --input data/sample_large.log
```

Mesures et méthodologie détaillées dans [BENCH.md](BENCH.md).
Résumé : **301 106×** de ratio taille fichier / RAM pic sur 12,11 Go (42 Ko RAM).

## Démo : voir chaque fonction "parler"

```powershell
python scripts/demo_functions.py --input data/sample_small.log
```

Déroule chaque fonction-clé (ingestion, filtres, transforms, router, analytics,
rule engine, introspection) avec son entrée et sa sortie réelles sur le dataset.
Utile pour la soutenance : prouve que chaque fonction produit des données, au-delà
des 40 tests pytest qui ne font que vérifier qu'elles renvoient le bon type.

## Rapport IP par IP (qui fait quoi)

```powershell
python scripts/ip_report.py --input data/sample_small.log --top 50 --threshold 5
python scripts/ip_report.py --input data/sample_large.log --top 50
```

Tableau trié des IPs avec colonnes Total / Logins / OK / FAIL / ERROR et statut
BRUTEFORCE / BLACKLIST / OK. Répond à la question « parmi les 50 IPs, lesquelles
sont en bruteforce ? » que `main.py --rules bruteforce` ne détaille pas.

## Figures du rapport

```powershell
python scripts/make_figures.py --input data/sample_large.log --out figures/
```

Génère en une passe paresseuse via les générateurs :
- `figure_3_levels.png` : répartition des niveaux de sévérité
- `figure_4_top_error_ips.png` : top 10 des IPs en ERROR
- `figure_5_bruteforce.png` : top 10 des IPs avec tentatives bruteforce
- `stats.json` : agrégats bruts

## Qualité du code

```powershell
python -m ruff check src/ tests/
python -m black --check src/ tests/
```

## Équipe

- **Dev A — Mamadou NIANGADOU** : Module 1 (ingestion & générateurs) + script de génération + benchmark mémoire + figures matplotlib
- **Dev B — Marlon PERFILLON** : Module 2 (pipeline fonctionnel) + `main.py`
- **Dev C — Baptiste JULIEN** : Modules 3 & 4 (analytics & rule engine)
