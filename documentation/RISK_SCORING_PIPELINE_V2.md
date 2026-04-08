# Pipeline De Risk Scoring V2

## Vue d'ensemble

Le pipeline repose sur trois couches complémentaires:

1. `services/event-collector/main.py`
   Reçoit les événements réels, enrichit les signaux réseau/géo/historique, appelle `/score`, puis stocke le résultat dans `iam.login_events`.
2. `ml/training/*`
   Génère un dataset synthétique réaliste, extrait les vrais `LOGIN` depuis ClickHouse, applique un schéma commun, entraîne et sérialise le modèle.
3. `ml/scoring-service/app.py`
   Charge les artefacts, exécute la prédiction ML multiclasses, applique des règles critiques bloquantes et renvoie la décision MFA.

## Schéma commun

Le schéma partagé est centralisé dans `ml/training/pipeline_schema.py`.

### Features catégorielles
- `client_id`
- `ua_browser`
- `ua_os`
- `ua_device`
- `geo_country_code`
- `asn_org`

### Features numériques
- `app_sensitivity`
- `hour`
- `day_of_week`
- `is_weekend`
- `is_night_login`
- `is_business_hours`
- `is_new_device`
- `is_new_ip_for_user`
- `fails_5m`
- `fails_1h`
- `fails_24h`
- `login_1h`
- `is_vpn_detected`
- `is_proxy_detected`
- `is_tor`
- `distance_from_last_location_km`
- `is_impossible_travel`
- `abuse_confidence_score`

### Colonnes de provenance
- `synthetic_rule_score`: score généré par la logique synthétique, jamais utilisé comme feature de training
- `source_risk_score`
- `source_risk_label`
- `source_decision`
- `source_policy_reason`
- `data_origin`

## Clarification des scores

- `synthetic_rule_score`
  Score continu `0..1` produit seulement pour les données synthétiques afin d'expliquer la génération.
- `risk_score`
  Score final retourné par l'API de scoring en production.
- `model_risk_score`
  Score continu dérivé uniquement des probabilités ML multiclasses avant éventuelle surcharge par règle critique.

Le score ML suit cette formule:

```text
risk_score = sum(p_i * class_i) / (num_classes - 1)
```

avec le mapping:

- `0 = low`
- `1 = moderate`
- `2 = high`
- `3 = critical`

## Cible multiclasses

La cible d'entraînement est `risk_class`.

- `0 -> low`
- `1 -> moderate`
- `2 -> high`
- `3 -> critical`

Le dataset réel est exporté depuis `iam.login_events` en gardant seulement les vrais `LOGIN` réussis et scorés.

## Génération synthétique

Le générateur synthétique ne réutilise plus directement les règles MFA de production comme cible d'entraînement.

- il simule des profils utilisateurs, appareils, localisations, anomalies réseau et historique
- il calcule un `synthetic_rule_score` continu bruité
- la classe finale est dérivée par seuils sur ce score continu
- des facteurs cachés non observables par le modèle (`user_id`, `username`) ajoutent une part de variabilité pour éviter un apprentissage trop trivially rule-based

Cela réduit le risque que le modèle ne fasse que recopier des seuils métiers.

## Sélection de features

La sélection de features suit cette logique:

1. mRMR sur le split temporel d'entraînement uniquement
2. ranking complet sauvegardé dans `risk_model_v1_features.json`
3. génération de plusieurs candidats `top_k`
   - `6`
   - `8`
   - `10`
   - `12`
   - variante `positive_only`
4. suppression des features de fin de liste dont le score mRMR est nul ou négatif
5. comparaison des candidats sur validation

Le but est d'éviter de conserver des colonnes juste pour remplir artificiellement un top-k.

## Comparaison de modèles

Les modèles comparés sur le même split temporel sont:

- `LightGBM`
- `Logistic Regression`
- `Random Forest`
- `XGBoost`

Les métriques suivies sont:

- `accuracy`
- `balanced_accuracy`
- `macro_f1`
- `weighted_f1`
- `log_loss`
- `expected_calibration_error`
- `multiclass_brier_score`
- `macro_roc_auc_ovr`

Le meilleur modèle est choisi avec priorité aux performances de classification, puis à la qualité probabiliste et enfin à la parcimonie en features.

## Calibration

La calibration est testée proprement sans fuite:

1. apprentissage du modèle brut sur une sous-partie temporelle du train
2. calibration `sigmoid` sur un holdout temporel disjoint
3. comparaison `raw` vs `calibrated` sur la validation
4. conservation de la calibration uniquement si elle améliore réellement la qualité probabiliste sans dégrader la classification

Si la calibration n'apporte pas de gain net, le pipeline conserve les probabilités brutes du modèle.

## Hybridation règles + ML

Ordre exact d'évaluation dans `ml/scoring-service/app.py`:

1. normalisation robuste du payload
2. prédiction ML multiclasses
3. calcul du `model_risk_score`
4. application des hard rules critiques
5. mapping final vers politique MFA

Les hard rules ne servent qu'aux cas extrêmes:

- volume de fails anormal
- application très sensible + anomalies majeures
- impossible travel critique
- abuse score fort avec proxy/Tor

Sinon, la décision suit le modèle ML.

### Impossible travel et VPN

Le collector calcule le voyage impossible même si l'IP courante est un VPN/proxy, car c'est précisément un cas intéressant de détection.

La règle appliquée est:

- la connexion courante peut être VPN/proxy/Tor
- la comparaison se fait d'abord avec la dernière position historique fiable, c'est-à-dire un `LOGIN` réussi sans VPN, proxy ni Tor
- si aucune position fiable n'existe, le collector retombe sur la dernière position distincte disponible
- un déplacement `>= 500 km` à une vitesse `>= 900 km/h` positionne `is_impossible_travel=1`

Côté scoring:

- impossible travel + application sensible/proxy/Tor/abuse fort -> `critical`
- impossible travel + VPN ou nouvelle IP/device -> `high`
- impossible travel isolé -> `moderate`
- VPN/proxy/Tor + nouvelle IP + déplacement long mais temporellement possible -> `moderate`, ou `high` si l'application est sensible

Cela évite qu'un VPN distant avec nouvelle IP retourne un score quasi nul, tout en ne le classant pas automatiquement `critical` quand le délai entre les deux connexions rend le déplacement possible.

Le mode privé du navigateur n'est pas utilisé comme signal direct: les navigateurs ne l'exposent pas de façon fiable côté serveur. Il peut seulement avoir un effet indirect si le fingerprint, les cookies ou les signaux de session changent réellement.

### Événements MFA / TOTP

Keycloak émet aussi un événement `LOGIN` quand le client de step-up TOTP termine la vérification du one-time code. Cet événement n'est pas un nouveau login métier: c'est la finalisation du second facteur.

Le collector traite donc les clients définis dans `STEP_UP_CLIENT_IDS` (par défaut `portal-stepup-totp-client`) de façon spécifique:

- l'événement TOTP hérite du dernier `LOGIN` applicatif récent du même utilisateur et de la même IP
- le `risk_score` et le `risk_label` restent ceux du risque initial, par exemple `0.35 / moderate`
- si le risque initial demandait TOTP, la décision de l'événement TOTP devient `ALLOW`, avec `auth_path=MFA_COMPLETED`
- les clients step-up sont exclus des compteurs historiques et de l'export training, pour éviter que le second facteur gonfle artificiellement `login_1h` ou apprenne au modèle un faux login `low`

Côté Keycloak, le client `portal-stepup-totp-client` doit utiliser un flow browser dédié avec:

- `Cookie` en `REQUIRED`, pour réutiliser la session SSO créée par le login principal
- `OTP Form` en `REQUIRED`

Cela évite de redemander `username + password` pendant un step-up: le second facteur doit être un contrôle supplémentaire, pas un second login complet.

Le script reproductible est:

```powershell
python scripts/configure_keycloak_stepup_totp.py
```

## Mapping classe -> décision MFA

- `low`
  `ALLOW`, facteur `NONE`, chemin `SSO_ONLY`
- `moderate`
  `STEP_UP_TOTP`, facteur `TOTP_OR_WEBAUTHN`, chemin `SECOND_FACTOR`
- `high`
  `STEP_UP_BIOMETRIC`, facteur `FACE_RECOGNITION`, chemin `BIOMETRIC_FACTOR`
- `critical`
  `BLOCK_REVIEW`, facteur `ADMIN_REVIEW`, chemin `TEMP_BLOCK`

## Résolution par disponibilité des facteurs

La décision de scoring ne suffit pas à elle seule: le portail résout ensuite la politique MFA selon les facteurs déjà enregistrés pour l'utilisateur.

Règle retenue:

- on n'enrôle jamais un nouveau facteur pendant une session déjà jugée risquée
- pour un risque `moderate`, un facteur plus fort déjà enregistré peut remplacer le TOTP
- pour un risque `high`, la biométrie reste obligatoire si la politique l'a demandée; on ne dégrade pas vers TOTP
- si aucun facteur exploitable n'existe, la session passe en `RECOVERY_REQUIRED`

Conséquences concrètes:

- `STEP_UP_TOTP` + TOTP configuré -> TOTP Keycloak
- `STEP_UP_TOTP` + TOTP indisponible + biométrie configurée -> fallback biométrique
- `STEP_UP_TOTP` + aucun autre facteur enregistré -> recovery contrôlée
- `STEP_UP_BIOMETRIC` + biométrie configurée -> vérification faciale
- `STEP_UP_BIOMETRIC` + biométrie non configurée -> recovery contrôlée, sans fallback TOTP

C'est le choix le plus défendable pour le projet:

- le risque reste piloté par le scoring
- l'exécution MFA tient compte des facteurs réellement disponibles
- la sécurité évite les contournements opportunistes pendant une session suspecte
- les futures évolutions naturelles sont un dashboard admin de reset MFA et des recovery codes à usage unique

## Onboarding MFA des nouveaux comptes

Le realm Keycloak ne doit pas forcer `CONFIGURE_TOTP` au premier login.

Pourquoi:

- un premier login ne prouve pas à lui seul que l'acteur est le vrai propriétaire du compte
- avec une simple connaissance du mot de passe initial, un attaquant pourrait sinon enrôler son propre téléphone avant l'utilisateur légitime
- l'enrôlement MFA doit donc être autorisé seulement depuis une session de confiance, via le portail

Conséquence retenue dans le projet:

- `CONFIGURE_TOTP` n'est plus une `defaultAction` globale dans Keycloak
- le portail propose la gestion OTP uniquement depuis une session `trusted`
- un step-up risqué ne crée jamais un nouveau facteur; il utilise un facteur déjà enregistré ou passe en `RECOVERY_REQUIRED`

Script de mise en conformité:

```powershell
python scripts/configure_keycloak_factor_bootstrap.py
```

## Bootstrap MFA, validation admin et recovery codes

La logique retenue maintenant est la suivante:

- `ALLOW` + aucun TOTP enregistrÃ© -> `ONBOARDING_REQUIRED`
- `moderate/high` + aucun facteur enregistrÃ© pour exÃ©cuter le step-up -> pas d'enrÃ´lement opportuniste dans la mÃªme session
- premier login non `low` sans TOTP -> `ADMIN_VALIDATION_REQUIRED`
- approbation admin -> fenÃªtre d'onboarding limitÃ©e dans le temps, pas d'ouverture directe de l'application
- recovery codes -> gÃ©nÃ©rÃ©s uniquement aprÃ¨s configuration TOTP, stockÃ©s hashÃ©s, utilisables une seule fois, et seulement pour un `STEP_UP_TOTP`

Ordre d'Ã©valuation:

1. le scoring produit la dÃ©cision de risque
2. le portail rÃ©sout les facteurs rÃ©ellement disponibles
3. si aucun TOTP n'existe encore:
   - risque `low` -> onboarding limitÃ©
   - risque supÃ©rieur Ã  `low` -> validation admin
4. si un `STEP_UP_TOTP` est demandÃ© mais que le tÃ©lÃ©phone manque:
   - biomÃ©trie dÃ©jÃ  configurÃ©e -> fallback biomÃ©trique
   - recovery code disponible -> fallback recovery code
   - sinon -> `RECOVERY_REQUIRED`

L'objectif est d'Ãªtre dÃ©fendable devant un jury:

- un mot de passe correct ne suffit pas Ã  prouver l'identitÃ© lors d'un premier bootstrap MFA
- un attaquant ne doit pas pouvoir enrÃ´ler son propre tÃ©lÃ©phone pendant une session dÃ©jÃ  suspecte
- l'admin valide uniquement le droit de bootstrap, pas l'ouverture directe de l'application

## Étude d'ablation

Le fichier `artifacts/risk_model_v1_ablation.json` sauvegarde trois vues:

- `baseline_core`
- `baseline_plus_network`
- `baseline_plus_network_geo_history`

Cela permet de montrer devant le jury l'apport des signaux réseau, géographiques et historiques.

## Robustesse

Les garde-fous principaux sont:

- schéma partagé centralisé
- coercition et valeurs par défaut côté API
- compatibilité de lecture des anciens artefacts
- validation des classes présentes avant training
- sélection de calibration sans fuite
- support explicite des colonnes absentes ou nulles
- tests automatisés de schéma, sélection et endpoint

## Commandes

Régénérer le dataset synthétique:

```powershell
python ml/training/generate_synthetic_dataset.py
```

Exporter les logins réels et reconstruire le dataset final:

```powershell
python ml/training/build_training_dataset.py
```

Réentraîner:

```powershell
python ml/training/train_risk_model.py
```

Lancer la chaîne automatique complète:

```powershell
python scripts/auto_train.py --biometric-check
```

Lancer la chaîne automatique et redémarrer le scoring runtime:

```powershell
python scripts/auto_train.py --biometric-check --restart-services
```

Le script automatique exécute:

- génération synthétique
- export des logins réels ClickHouse
- fusion du dataset final
- entraînement ML + sélection mRMR + comparaison de modèles
- tests unitaires et endpoint local via `TestClient`
- rapport JSON/Markdown dans `ml/training/reports`
- health check optionnel du service biométrique

`buffalo_l` n'est pas réentraîné par ce projet: c'est un modèle InsightFace pré-entraîné. L'automatisation vérifie sa disponibilité et son préchargement côté `biometric-service`.

## Scheduler automatique

Le service Docker Compose `training-scheduler` permet un retraining sans commande manuelle répétée.

Comportement par défaut:

- démarrage avec la stack Docker
- attente initiale de `300` secondes
- retraining toutes les `86400` secondes
- génération synthétique + export réel + training + tests + promotion gate
- rapport dans `ml/training/reports`
- check de disponibilité `buffalo_l`

Variables utiles:

- `AUTO_TRAIN_ENABLED`
- `AUTO_TRAIN_INTERVAL_SECONDS`
- `AUTO_TRAIN_INITIAL_DELAY_SECONDS`
- `AUTO_TRAIN_RUN_ON_START`
- `AUTO_TRAIN_MIN_MACRO_F1`
- `AUTO_TRAIN_MIN_BALANCED_ACCURACY`

Le `scoring-service` recharge automatiquement les artefacts si le modèle change; il n'est donc pas nécessaire de redémarrer le service après chaque retraining automatique.

Lancer ou relancer le service:

```powershell
docker compose up -d --build scoring-service event-collector
```

Tester l'API:

```powershell
Invoke-RestMethod -Method Post -Uri http://localhost:8090/score -ContentType 'application/json' -Body '{"client_id":"portal-main-client","app_sensitivity":1,"ua_browser":"Brave 146.0.0.0","ua_os":"Windows 11","ua_device":"pc","geo_country_code":"TN","asn_org":"Orange Tunisie","hour":10,"day_of_week":5,"is_weekend":0,"is_night_login":0,"is_business_hours":1,"is_new_device":0,"is_new_ip_for_user":0,"fails_5m":0,"fails_1h":0,"fails_24h":0,"login_1h":1,"is_vpn_detected":0,"is_proxy_detected":0,"is_tor":0,"distance_from_last_location_km":0,"is_impossible_travel":0,"abuse_confidence_score":0}'
```
