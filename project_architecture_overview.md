# Projet Architecture Overview - SSO + MFA + IA (PFE-_SSO_MFA-IA)
*Generated: Analyse complète de l'état actuel du projet pour envoi à un AI*
*Working Directory: `c:/Users/SBS/Desktop/PFE 2026/SSO + GH/PFE-_SSO_MFA-IA`*

## 1. Vue d'Ensemble Haute Niveau
Ce projet est une **plateforme SSO (Single Sign-On) avec MFA (Multi-Factor Authentication) et IA pour Risk-Based Authentication**. 
- **Authentification centrale**: Keycloak avec SPI custom pour événements risque.
- **Services Microservices**: Python (FastAPI/Flask) pour biometric, event collection, ML scoring.
- **Frontend/Portails**: Node.js servers pour CRM, HR, Finance, Portal, Admin.
- **ML/IA**: Modèles de risk scoring (entraînement + inférence en production).
- **Stockage/Analytics**: ClickHouse (inféré des docs), données synthétiques/réelles.
- **Déploiement**: Docker Compose + Nginx reverse proxy.
- **Données**: GeoIP, biométrie, logs événements, datasets ML.

### Diagramme Architecture (Text-based Mermaid-like)
```
[Users] --> Nginx (infra/nginx/default.conf)
Nginx --> Node.js Portals (SP/portal, crm, hr, finance, admin)
Portals <--> Keycloak (realm-full.json + kc-spi)
Keycloak --> RiskEventListener SPI (Java) --> EventCollector (Python)
EventCollector --> ClickHouse (enrichment.py)
BiometricService (Python) <--> Portals (storage.py)
ML Scoring (app.py) <--> Risk Model (train_risk_model.py)
ML Training (offline: generate_synthetic_dataset.py)
```

## 2. Structure Complète des Fichiers et Dossiers
```
PFE-_SSO_MFA-IA/
├── .gitignore
├── docker-compose.yml                  # Orchestration tous services
├── GeoIP.conf(.example)               # GeoIP pour risk scoring
├── README.md
├── realm-full.json                    # Config Keycloak realm
├── data/                              # Données brutes
├── documentation/                     # Guides détaillés
│   ├── ANALYSE_ETAT_PROJET.md
│   ├── analyse_globale.md
│   ├── GUIDE_DEPLOIEMENT.txt
│   ├── INTEGRATION_COMPLETE_V2.md
│   └── ... (ClickHouse guides, ML analysis)
├── infra/
│   └── nginx/default.conf             # Reverse proxy
├── keycloak-spi/                      # Extension Keycloak (Java/Maven)
│   └── kc-event-listener/
│       ├── pom.xml
│       ├── RiskEventListenerProvider.java
│       └── RiskEventListenerProviderFactory.java
├── ml/                                # Machine Learning
│   ├── training/                      # Entraînement offline
│   │   ├── train_risk_model.py
│   │   ├── generate_synthetic_dataset.py
│   │   ├── build_training_dataset.py
│   │   ├── requirements.txt
│   │   └── data/ (real_export.csv, synthetic_risk_dataset.csv, etc.)
│   └── scoring-service/               # Inférence temps réel
│       ├── app.py
│       ├── Dockerfile
│       └── requirements.txt
├── services/                          # Microservices Python
│   ├── biometric-service/
│   │   ├── main.py
│   │   ├── storage.py
│   │   ├── Dockerfile
│   │   └── requirements.txt
│   └── event-collector/
│       ├── main.py
│       ├── enrichment.py
│       ├── Dockerfile
│       └── requirements.txt
└── SP/                                # Single Page Apps / Portails Node.js
    ├── package.json / package-lock.json
    ├── shared/oidc.js                 # OIDC config partagé
    ├── admin/server.js
    ├── crm/server.js
    ├── finance/server.js
    ├── hr/server.js
    └── portal/server.js
```

## 3. Composants Clés et Dépendances
| Composant | Langage/Tech | Rôle | Fichiers Principaux | Dépendances |
|-----------|--------------|------|---------------------|-------------|
| **Keycloak SPI** | Java (Maven) | Écouteur événements risque → EventCollector | `RiskEventListenerProvider.java` | Keycloak API |
| **Event Collector** | Python (FastAPI?) | Collecte/agrège événements → ClickHouse | `main.py`, `enrichment.py` | ClickHouse client |
| **Biometric Service** | Python | Stockage/gestion biométrie | `main.py`, `storage.py` | DB (SQLite?) |
| **ML Training** | Python (Scikit-learn?) | Génère dataset synthétique, entraîne modèle risque | `train_risk_model.py`, `generate_synthetic_dataset.py` | Pandas, Scikit-learn |
| **ML Scoring** | Python (FastAPI) | Score risque en temps réel | `app.py` | Modèle .pkl (artifacts/) |
| **Node.js Portals** | Node.js (Express?) | Interfaces CRM/HR/Finance/Portal/Admin | `server.js` chacun | OIDC (shared/oidc.js) |
| **Nginx** | Nginx | Reverse proxy pour tous portails | `default.conf` | Docker |
| **Keycloak** | Keycloak | SSO/MFA central | `realm-full.json` | Custom SPI |

- **Docker**: Tous services Dockerisés (`Dockerfile` partout) + `docker-compose.yml`.
- **ML Data**: Datasets réels/synthétiques → `training_dataset_final.csv`.
- **Documentation**: Très complète (déploiement, intégration, ClickHouse features).

## 4. Fichiers Ouverts/Visibles (État Actuel VSCode)
- **Visible**: `services/event-collector/main.py`
- **Tabs Ouverts**: Focus sur ML (`train_risk_model.py`, `app.py`), Biometric (`main.py`, `storage.py`), Portals Node.js (`server.js`), Dockerfiles, docs (`ANALYSE_ETAT_PROJET.md`), et patches externes (Downloads/biometric_integration_patch).

## 5. Statut Projet (Inféré)
- **Avancé**: Architecture complète, services implémentés, ML entraîné, docs exhaustives.
- **Points d'Intégration**: Keycloak SPI → EventCollector → ML Scoring → MFA decisions.
- **Prochaine Étape Potentielle**: Déploiement prod (docker-compose up), tests E2E, monitoring.

Ce fichier est autonome et prêt à être envoyé à un AI pour analyse approfondie. Copiez-le ou joignez-le directement.

