# Training Risk Model

Ce dossier contient le pipeline de training du modèle de risk scoring.

## Scripts
- `generate_synthetic_dataset.py`: génère des `LOGIN` synthétiques proches du schéma réel
- `build_training_dataset.py`: fusionne synthétique + export réel ClickHouse
- `train_risk_model.py`: sélection mRMR, comparaison de modèles, calibration, sauvegarde des artefacts
- `pipeline_schema.py`: schéma partagé entre dataset, training et scoring API

## Artefacts produits
- `artifacts/risk_model_v1.joblib`
- `artifacts/risk_model_v1_features.json`
- `artifacts/risk_model_v1_model_comparison.json`
- `artifacts/risk_model_v1_ablation.json`

## Exécution
```powershell
pip install -r ml/training/requirements.txt
python ml/training/generate_synthetic_dataset.py
python ml/training/build_training_dataset.py
python ml/training/train_risk_model.py
```

## Automatisation

Pour lancer la chaîne complète avec génération, export réel, training mRMR/modèles, tests et rapport:

```powershell
python scripts/auto_train.py --biometric-check
```

Pour redémarrer aussi le runtime de scoring après succès:

```powershell
python scripts/auto_train.py --biometric-check --restart-services
```

Note: `buffalo_l` est un modèle InsightFace pré-entraîné. Le script vérifie sa disponibilité via le service biométrique, mais ne le réentraîne pas.

## Scheduler Docker

Le service `training-scheduler` dans `docker-compose.yml` lance automatiquement le retraining à intervalle régulier.

Variables principales:
- `AUTO_TRAIN_ENABLED=true`
- `AUTO_TRAIN_INTERVAL_SECONDS=86400`
- `AUTO_TRAIN_INITIAL_DELAY_SECONDS=300`
- `AUTO_TRAIN_RUN_ON_START=false`
- `AUTO_TRAIN_MIN_MACRO_F1=0.80`
- `AUTO_TRAIN_MIN_BALANCED_ACCURACY=0.75`

Le `scoring-service` recharge automatiquement le modèle si `risk_model_v1.joblib` ou `risk_model_v1_features.json` changent.
