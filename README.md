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

# Dataset complet (10-15 Go, plusieurs minutes)
python scripts/generate_logs.py --out data/sample_large.log --gb 12
```

## Lancement du pipeline

```powershell
python main.py --input data/sample_small.log --limit 10
```

## Tests

```powershell
pytest -v
```

## Équipe

- **Dev A — Mniangadou** : Module 1 (ingestion & générateurs) + script de génération
- **Dev B — Marlon** : Module 2 (pipeline fonctionnel) + `main.py`
- **Dev C — Baptiste** : Modules 3 & 4 (analyse & rule engine) + notebook de démo
