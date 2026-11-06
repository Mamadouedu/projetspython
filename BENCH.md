# Benchmark mémoire du pipeline d'ingestion (Dev A)

Preuve que l'approche **générateur** (`yield` + `yield from`) lit un fichier
arbitrairement gros sans accumuler en RAM.

## Méthode

```powershell
python scripts/bench_memory.py --input data/sample_large.log
```

Le script instrumente `tracemalloc` autour de la lecture complète du
fichier via `read_log_file()` et du parsing de chaque ligne via
`parse_line()`.

## Résultats mesurés (2026-11-05)

| Fichier | Lignes | Valides | Rejetées | RAM pic | Ratio fichier/RAM |
| --- | --- | --- | --- | --- | --- |
| `sample_small.log` (5,2 Mo) | 49 850 | 47 358 | 2 492 (5,0 %) | **0,038 Mo** | **136×** |
| `sample_large.log` (2,75 Go) | 27 180 284 | 25 863 124 | 1 317 160 (4,8 %) | **0,061 Mo** | **46 400×** |

- **Machine** : Windows 11, Python 3.12.3.
- **Débit** : ~2,4 Mo/s · ~23 500 lignes/s (CPU-bound sur le parser).
- **Verdict** : la RAM reste **plate quelle que soit la taille d'entrée**.
  Passer de 5 Mo à 2,75 Go (×540) n'augmente la mémoire que de 25 Ko.

## Reproduire

```powershell
# Générer un échantillon ou le dataset complet
python scripts/generate_logs.py --out data/sample_large.log --gb 12

# Mesurer
python scripts/bench_memory.py --input data/sample_large.log
```

Les résultats sont reproductibles avec `--seed 42` sur le générateur.
