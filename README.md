# SSO + MFA + IA — Système d'Authentification Adaptative

> Projet de Fin d'Études — Architecture microservices avec Keycloak, OIDC, MFA et scoring IA (LightGBM)

---

## 📁 Structure du monorepo

```
sso-mfa-ia-project/
│
├── services/                    # Microservices backend
│   ├── keycloak/                # Configuration et extensions Keycloak (IdP)
│   ├── ai-risk-service/         # Service IA de scoring de risque (Python/FastAPI)
│   ├── api-gateway/             # Passerelle API (Kong / Traefik)
│   ├── audit-service/           # Journalisation et export SIEM
│   ├── notification-service/    # Alertes email/SMS
│   └── mfa-service/             # Gestion des facteurs MFA
│
├── apps/                        # Applications clientes de démonstration
│   ├── web-client/              # Frontend React (application protégée par SSO)
│   └── demo-api/                # API REST protégée (FastAPI)
│
├── infra/                       # Infrastructure as Code
│   ├── docker/                  # Dockerfiles spécifiques
│   ├── kubernetes/              # Manifests K8s et charts Helm
│   └── scripts/                 # Scripts d'initialisation et d'automatisation
│
├── data/                        # Données ML
│   ├── datasets/                # Dataset RBA et données générées
│   └── models/                  # Modèles entraînés (.pkl, .lgbm)
│
├── docs/                        # Documentation du projet
│   ├── architecture/            # Schémas et décisions d'architecture
│   ├── api/                     # Documentation des APIs
│   └── guides/                  # Guides d'installation et d'utilisation
│
├── .github/workflows/           # Pipelines CI/CD (GitHub Actions)
├── docker-compose.yml           # Orchestration dev/test complète
├── docker-compose.override.yml  # Overrides locaux (non commité)
├── .env.example                 # Variables d'environnement (modèle)
└── Makefile                     # Commandes pratiques (make up, make test...)
```

---

## 🚀 Démarrage rapide

### Prérequis
- Docker >= 24.x
- Docker Compose >= 2.x
- Python 3.11+
- Node.js 18+ (pour le frontend)
- Git

### Installation

```bash
# 1. Cloner le dépôt
git clone https://github.com/<ton-username>/sso-mfa-ia-project.git
cd sso-mfa-ia-project

# 2. Copier les variables d'environnement
cp .env.example .env
# → Éditer .env avec tes valeurs

# 3. Lancer toute la stack
make up
# ou : docker compose up -d

# 4. Accéder aux services
# Keycloak Admin : http://localhost:8080
# Service IA     : http://localhost:8001/docs
# App Web        : http://localhost:3000
# Kibana (logs)  : http://localhost:5601
```

---

## 🧩 Services

| Service | Port | Technologie | Description |
|---------|------|-------------|-------------|
| Keycloak | 8080 | Java / Quarkus | Fournisseur d'identité SSO |
| PostgreSQL | 5432 | PostgreSQL 15 | Base de données Keycloak |
| AI Risk Service | 8001 | Python / FastAPI | Scoring de risque IA |
| API Gateway | 8000 | Kong / Traefik | Point d'entrée unique |
| Audit Service | 8002 | Python / FastAPI | Logs et journalisation |
| Notification | 8003 | Python / FastAPI | Alertes email/SMS |
| Web Client | 3000 | React / Vite | App démo protégée par SSO |
| Demo API | 8004 | FastAPI | API protégée par JWT |
| Elasticsearch | 9200 | Elasticsearch 8 | Stockage des logs |
| Kibana | 5601 | Kibana 8 | Dashboard de monitoring |

---

## 🌿 Branches Git

| Branche | Usage |
|---------|-------|
| `main` | Code stable, validé |
| `develop` | Intégration continue |
| `feature/keycloak-setup` | Développement d'une fonctionnalité |
| `feature/ai-scoring` | Module IA |
| `fix/mfa-flow` | Correction de bug |
| `release/v1.0` | Préparation release |

---


---

## 📄 Licence
Projet académique — Usage interne PFE uniquement.
