# Benchmark mémoire du pipeline d'ingestion (Dev A)

Preuve que l'approche **générateur** (`yield` + `yield from`) lit un fichier
arbitrairement gros sans accumuler en RAM.

## Méthode

Le script `bench_memory.py` instrumente `tracemalloc` autour de la lecture
complète du fichier. Deux modes :

- **read-only** (`--read-only`) : mesure seulement la lecture via
  `read_log_file()` (générateur `yield` + `yield from`). Rapide, prouve
  que la lecture streamée ne charge rien en RAM.
- **read+parse** (par défaut) : lit *et* parse chaque ligne via
  `parse_line()`. Plus lent (parser CPU-bound), prouve que le pipeline
  complet ne charge rien non plus.

## Résultats mesurés

| Fichier | Mode | Lignes | RAM pic | Ratio fichier/RAM | Débit |
| --- | --- | --- | --- | --- | --- |
| `sample_small.log` (5,2 Mo) | read+parse | 49 850 | **0,038 Mo** | **136×** | 1,8 Mo/s |
| `sample_large.log` (2,75 Go) | read+parse | 27 180 284 | **0,061 Mo** | **46 400×** | 2,4 Mo/s |
| `sample_large.log` (**12,11 Go**) | read-only | **119 510 991** | **0,041 Mo** | **301 106×** | 28,4 Mo/s |

- **Machine** : Windows 11, Python 3.12.3.
- **Verdict** : la RAM reste **plate quelle que soit la taille d'entrée**.
  Passer de 5 Mo à 12 Go (×2 400) ne fait pas bouger la RAM : elle reste
  autour de 40-60 Ko. Le ratio fichier/RAM grandit linéairement avec la
  taille du fichier — preuve directe que l'approche générateur
  (`yield` + `yield from`) ne garde aucune ligne en mémoire.

## Reproduire

```powershell
# Générer le dataset complet (16 min, ~12 Go)
python scripts/generate_logs.py --out data/sample_large.log --gb 12 --seed 42

# Bench rapide (lecture seule, ~7 min sur 12 Go)
python scripts/bench_memory.py --input data/sample_large.log --read-only

# Bench complet avec parsing (~90 min sur 12 Go)
python scripts/bench_memory.py --input data/sample_large.log
```

Les résultats sont reproductibles avec `--seed 42` sur le générateur.
