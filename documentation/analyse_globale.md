# Analyse globale du projet

> Document de synthèse sur l'état actuel du code, les problèmes identifiés et les axes d'amélioration.

---

## 1. Contexte & périmètre

Ce dépôt implémente un prototype de **SSO / MFA / scoring IA** basé sur :

- **Keycloak** comme fournisseur d'identité (IdP) et source d'événements.
- **Un SPI Keycloak** (`keycloak-spi/kc-event-listener`) qui envoie les événements de connexion à un collecteur.
- **Un service `event-collector`** (FastAPI) qui enrichit les événements (IP, Geo, abuse, ML, etc.) et les stocke dans ClickHouse.
- **Des applications clientes** (`SP/*`) qui utilisent **openid-client** pour s’authentifier via Keycloak.

Le flux principal est :

`Keycloak -> SPI (event listener) -> event-collector -> ClickHouse`.

---

## 2. Architecture actuelle (vue d'ensemble)

### 📦 Composants principaux

- **Keycloak** (Java/Quarkus)
  - Realm configuré via `keycloak/realm-full.json`.
  - Extension SPI : `keycloak-spi/kc-event-listener`.

- **Event Collector** (`services/event-collector`)
  - FastAPI + enrichissement (GeoIP, AbuseIPDB, GreyNoise, VirusTotal, etc.)
  - Stockage en **ClickHouse**.
  - Beaucoup de calculs heuristiques et de variables de risque.

- **SP (Service Provider)** (`SP/portal`, `SP/crm`, etc.)
  - Plusieurs micro-apps Express utilisant `openid-client`.
  - Exemple : `SP/portal/server.js`.

- **Infrastructure**
  - `docker-compose.yml` orchestre l’ensemble.
  - `data/GeoLite2-City.mmdb` pour la géolocalisation.

---

## 3. Etat actuel du projet (observation rapide)

### ✅ Ce qui fonctionne (apparent)

- Le listener Keycloak collecte des événements Login/Login_Error et les envoie au collecteur.
- Le collecteur calcule des dizaines de features et persiste dans ClickHouse.
- Le `SP/portal` propose un login basique OIDC, une page protégée et un logout.

### ⚠️ Ce qui est incomplet / fragile

- Le route `/change-password` dans `SP/portal/server.js` est **inachevé** et ne marche pas (pas de parsing `req.body`).
- De nombreux composants n’ont **pas de tests automatisés**.
- Le projet manque de **contrôle de configuration** (`.env`/variables) et de validation.

---

## 4. Bugs & points faibles identifiés (analyse)

### 4.1. **SP / Portal (Express)**

- **Absence de `express.json()` / body parsing** : la route `POST /change-password` lit `req.body` mais aucune middleware n’est configurée, donc `req.body` sera `undefined`.
- **Session non sécurisée** :
  - `session({ secret: ..., resave: false, saveUninitialized: false })` sans `cookie.secure`, sans durée (`maxAge`) et avec un secret par défaut `change_me`.
  - Le domaine ne force pas HTTPS ni les flags `SameSite`.
- **URLs et secrets codés en dur** :
  - `KC_BASE_URL`, `APP_BASE_URL` par défaut pointent vers des tunnels Cloudflare.
  - Les valeurs de `CLIENT_ID`/`REALM` sont statiques.
- **Gestion du logout fragile** :
  - Si `issuerUrl` n’est pas initialisé ou si `id_token` absent, le logout redirige sur `APP_BASE_URL` mais peut casser en local.
- **Accès RBAC implémenté en dur** :
  - Seuls `ceo`, `manager`, `employee` autorisés, pas de gestion dynamique selon configuration.

### 4.2. **Event-Collector (FastAPI)**

- **Injection SQL / formatage manuel** :
  - `ch_query` construit des requêtes SQL en concaténant des chaînes.
  - Bien que `sql_escape()` existe, elle n’est pas utilisée partout (ex. `event_type`, `client_id`, etc.), ce qui peut poser un risque injection.
- **Absence de gestion d’erreur robuste** :
  - `ch_query` lève si ClickHouse est indisponible (pas de retry, pas de fallback).
  - Plusieurs fonctions (AbuseIPDB, GreyNoise, VirusTotal, etc.) font des appels HTTP sans circuit-breaker/timeout configurable.
- **Caches en mémoire non partagés** :
  - En cas de déploiement multi-instance, chaque instance recharge sa liste TOR, etc.
- **Absence d’authentification / authorization** :
  - Les endpoints `/events` et `/check-password` sont exposés sans protection.
- **Logs non structurés / debug en clair** :
  - Utilisation de `print()` partout (pas de niveau de log, de rotation, de traces structurées).
- **Chargement non conditionnel de GeoIP** :
  - La dépendance `geoip2` est optionnelle, mais le chemin du fichier est hardcodé (`/app/data/GeoLite2-City.mmdb`).
- **Performance / scalabilité** :
  - Requêtes ClickHouse en série par event; pas de batch.
  - Enrichissements bloquants (requests sync) dans le chemin critique.

### 4.3. **Keycloak SPI**

- **Pas de retry** lors de l’envoi à `collectorUrl` : si le collecteur est indisponible, l’événement est perdu.
- **Aucune authentification** : le collecteur est appelé en clair (pas de JWT, pas de signature). Un attaquant peut spammer le collecteur.
- **Logs verbeux** (print stacktraces) dans la console Keycloak.

### 4.4. **Infrastructure & DevOps**

- Le repo contient un seul `docker-compose.yml` (non inspecté ici) et peut manquer de configuration réseau claire pour Keycloak / services.
- Aucun pipeline CI/CD visible (absence de `.github/workflows` dans l’arborescence listée, bien que README le mentionne).

---

## 5. Recommandations d’amélioration (priorités)

### 🛡️ Sécurité (prioritaire)

1. **Renforcer la configuration des sessions** (`secure`, `httpOnly`, `sameSite`, `maxAge`).
2. **Authentifier les appels du SPI vers le collecteur** (JWT, HMAC, API key).
3. **Ajouter une configuration centralisée** (ex.: `envalid`, `pydantic.BaseSettings`) et valider les variables d’environnement au démarrage.
4. **Limiter l’exposition du collecteur** (IP whitelisting, firewall, auth).

### 🧰 Qualité & maintenabilité

1. Écrire des **tests unitaires et d’intégration** (coverage minimale sur le risque/score).
2. Ajouter un **linting / formatage** (ESLint, Prettier, Black, etc.).
3. Remplacer les `print()` par un logger configurable (niveau, format JSON, rotation).
4. Supprimer / factoriser le code dupliqué (ex. les calculs de features, l’extraction d’IP).

### ⚙️ Robustesse & scalabilité

1. **Isoler la logique d’enrichissement** (factories / plugins) pour faciliter l’ajout/retrait de sources.
2. **Utiliser une file d’attente** (Kafka/RabbitMQ) pour découpler la collecte d’événements et le calcul de risque.
3. **Batcher les écritures ClickHouse** pour améliorer les performances.
4. **Ajouter des métriques** (Prometheus) + healthchecks.

### 🔍 Observabilité

1. Centraliser les logs et erreurs (ELK/EFK, Sentry).
2. Créer des dashboards de risques/alertes basiques.
3. Ajouter des traces (OpenTelemetry) pour suivre le flux Keycloak -> collecteur.

---

## 6. Propositions rapides (quick wins)

- Corriger immédiatement `SP/portal/server.js` en ajoutant `app.use(express.json())` (et `express.urlencoded()`) pour que `/change-password` fonctionne.
- Ajouter un middleware `helmet()` + `cors()` configuré sur les apps Express.
- Remplacer `requests.post()` par une session persistante dans `services/event-collector` (évite la surconsommation de connexions).
- Ajouter des tests smoke (`pytest` / `jest`) pour les endpoints critiques.

---

## 7. Feuille de route “rendre le projet parfait”

Voici une proposition de **features & chantiers** pour transformer le prototype en solution solide et production-ready.

### ✅ 7.1. Sécurité & conformité

- Authentifier toutes les communications inter-services (SPI → collector, API → backend) via JWT, HMAC ou API key.
- Encrypter/sécuriser les secrets (Vault, HashiCorp, AWS Secrets Manager, etc.).
- Ajouter une gouvernance RBAC/ABAC configurable en base (Keycloak + config métier).
- Implémenter le support MFA adapté (envoi SMS/Email, TOTP, WebAuthn) et l’enregistrement de méthodes.
- Ajouter un module de “Security Posture” (scan d’infrastructure et détection de configuration dangereuse).

### ✅ 7.2. Robustesse & résilience

- Passage en architecture **event-driven** : collecter + bufferiser les événements (Kafka/RabbitMQ) puis traiter en batch.
- Level de retry / backoff exponentiel pour les appels distants (ClickHouse, APIs externes, services internes).
- Déploiement multi-az / multi-instance : partager cache (Redis, Memcached), éviter les caches locaux non cohérents.
- Healthchecks / readiness + liveness pour chaque service.

### ✅ 7.3. Observabilité & exploitation

- Logs structurés (JSON) + centralisation (ELK/EFK, Datadog, Grafana Cloud).
- Tracing distribué (OpenTelemetry) pour suivre un login Keycloak jusqu’au calcul de risque.
- Metrics métier (nombre d’événements traités, scores calculés, taux de rejet MFA) + dashboards Grafana.
- Alerting (SIEM, PagerDuty) sur seuils critiques (attaque brute-force, score élevé, etc.).

### ✅ 7.4. Qualité du code & développeur

- Ajouter une suite de tests : unitaires, d’intégration (docker-compose test), end-to-end (Cypress/Playwright).
- Mettre en place CI/CD (GitHub Actions / GitLab CI) avec lint, audit de dépendances, tests et build.
- Documenter l’architecture (diagrammes, conventions, guide de contribution).
- Ajouter une couche de documentation API (OpenAPI/Swagger) pour chaque service.

### ✅ 7.5. Expérience utilisateur

- UI de portail plus riche (dashboard, journal de connexion, actions MFA, notifications).
- Self-service (réinitialisation de mot de passe, gestion des devices, authentifieurs inscrits).
- Support multi-langue + accessibilité.

---

> 📌 Note : cette analyse est basée sur l’état actuel du code visible dans le dépôt. Des parties non inspectées (ex : `docker-compose.yml`, scripts infra, configuration Keycloak complète) peuvent ajouter des éléments supplémentaires à prendre en compte.
