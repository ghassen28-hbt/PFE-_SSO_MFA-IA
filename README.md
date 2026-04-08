# PFE SSO + MFA + IA

Architecture de démonstration pour une authentification adaptative basée sur Keycloak, MFA, scoring de risque ML et audit des événements.

## Services principaux
- `keycloak`: SSO/OIDC et orchestration MFA
- `event-collector`: enrichissement des événements de login et persistance ClickHouse
- `scoring-service`: inférence du modèle de risque multiclasses + règles critiques
- `SP/*`: applications clientes de démonstration

## Pipeline ML
Le pipeline complet de risk scoring est documenté ici:

- [documentation/RISK_SCORING_PIPELINE_V2.md](/c:/Users/SBS/Desktop/PFE%202026/SSO%20+%20GH/PFE-_SSO_MFA-IA/documentation/RISK_SCORING_PIPELINE_V2.md)

## Commandes utiles

Régénérer le dataset synthétique:

```powershell
python ml/training/generate_synthetic_dataset.py
```

Reconstruire le dataset final synthétique + réel:

```powershell
python ml/training/build_training_dataset.py
```

Réentraîner le modèle:

```powershell
python ml/training/train_risk_model.py
```

Lancer le retraining automatique complet:

```powershell
python scripts/auto_train.py --biometric-check
```

Le mode 100% automatique est aussi activé dans Docker Compose via `training-scheduler`: après démarrage de la stack, il relance périodiquement le pipeline selon `AUTO_TRAIN_INTERVAL_SECONDS` et le scoring service recharge les nouveaux artefacts automatiquement.

Relancer les services de scoring:

```powershell
docker compose up -d --build scoring-service event-collector
```

Tester l'API:

```powershell
Invoke-RestMethod -Method Post -Uri http://localhost:8090/score -ContentType 'application/json' -Body '{"client_id":"portal-main-client","app_sensitivity":1,"ua_browser":"Brave 146.0.0.0","ua_os":"Windows 11","ua_device":"pc","geo_country_code":"TN","asn_org":"Orange Tunisie","hour":10,"day_of_week":5,"is_weekend":0,"is_night_login":0,"is_business_hours":1,"is_new_device":0,"is_new_ip_for_user":0,"fails_5m":0,"fails_1h":0,"fails_24h":0,"login_1h":1,"is_vpn_detected":0,"is_proxy_detected":0,"is_tor":0,"distance_from_last_location_km":0,"is_impossible_travel":0,"abuse_confidence_score":0}'
```
