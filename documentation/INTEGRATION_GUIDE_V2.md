# Integration Guide: Event Collector v2 with 35 Advanced Features

## Overview

This guide explains how to integrate the new **enrichment_advanced.py** module into the Event Collector service to enable all 35 advanced features for comprehensive login risk analysis.

## Architecture Overview

```
Nginx (reverse proxy)
    ↓ (X-Forwarded-For header)
Keycloak 26.0.0 (with KC_PROXY=edge)
    ↓ (RiskEventListenerProvider)
Event Collector FastAPI (v2)
    ├─ Basic Enrichment (51 features)
    │  ├─ IP Abuse Score (AbuseIPDB)
    │  ├─ Geolocation (GeoLite2)
    │  ├─ Threat Intel (GreyNoise, Tor, VirusTotal)
    │  └─ Device Fingerprinting
    │
    ├─ Advanced Enrichment (35 new features)
    │  ├─ Groupe 13: Location History, Impossible Travel, VPN/Proxy
    │  ├─ Groupe 14: Behavior Analysis, Account Dormancy
    │  ├─ Groupe 15: ML Anomaly Scoring (XGBoost)
    │  ├─ Groupe 16: MFA Tracking
    │  ├─ Groupe 17: Security Detection (ATO, Session Hijacking, Bots)
    │  ├─ Groupe 18: Predictive Risk
    │  ├─ Groupe 19: Compliance Classification
    │  └─ Groupe 20: SIEM/Threat Feed Integration
    │
    └─ ClickHouse v2 (86 columns)
        └─ login_events_v2 table
```

## Files in This Integration

### 1. **enrichment_advanced.py** (500+ lines)
Complete implementation of all 35 advanced features.

**Key Components:**
- Configuration section with API keys and thresholds
- 35 feature calculation functions organized by groupe
- `enrich_with_advanced_features()` - Main orchestration function
- `initialize()` - Setup function for caching and ML model

**Usage:**
```python
from enrichment_advanced import enrich_with_advanced_features, initialize

# On startup
initialize()

# During event processing
advanced_features = enrich_with_advanced_features(payload, user_history)
```

### 2. **main_v2.py** (Full integration)
Updated FastAPI application that integrates enrichment_advanced.py.

**Key Changes:**
- Imports `enrich_with_advanced_features` and `initialize`
- Calls `init_advanced()` on startup
- Creates table `login_events_v2` with 86 columns
- Calls `enrich_with_advanced_features()` after basic enrichment
- Merges results before ClickHouse insertion

### 3. **migration_v2_add_35_features.sql**
ClickHouse SQL migration script.

**Includes:**
- DDL for login_events_v2 table (86 columns)
- Index definitions for performance
- 5 analytical views for dashboards
- Partitioning strategy (daily by date, 90-day TTL)
- Dashboard queries for analysis

## Step-by-Step Integration

### Step 1: Update Environment Variables

Add to `docker-compose.yml` under the event-collector service:

```yaml
event-collector:
  build: ./services/event-collector
  environment:
    # ... existing vars ...
    
    # Advanced Features Configuration
    IPQS_API_KEY: "your_ipqs_api_key"                # IPQS for VPN/Proxy detection
    SIEM_WEBHOOK_URL: "http://siem:9999/events"     # SIEM webhook endpoint
    ML_MODEL_PATH: "/app/models/xgb_anomaly_model.pkl"
    
    # Thresholds
    VPN_DETECTION_THRESHOLD: "0.8"
    PROXY_DETECTION_THRESHOLD: "0.8"
    BOT_SCORE_THRESHOLD: "0.7"
    IMPOSSIBLE_TRAVEL_SPEED_KMH: "900"
    DORMANCY_DAYS: "30"
    
    # Classification
    BLOCKED_COUNTRIES: "IR,KP,SY"
    RESTRICTED_COUNTRIES: "CN,RU,KR"
    PCI_SENSITIVE_APPS: "finance,admin"
    HIPAA_SENSITIVE_APPS: "hr"
```

### Step 2: Backup Current Service

```bash
cd services/event-collector
cp main.py main_backup_$(date +%Y%m%d).py
cp requirements.txt requirements_backup_$(date +%Y%m%d).txt
```

### Step 3: Add Dependencies

Update `requirements.txt`:

```
fastapi==0.104.1
uvicorn==0.24.0
clickhouse-connect==0.7.7
requests==2.31.0
user-agents==2.3.0
scikit-learn==1.3.2
xgboost>=1.7.6
numpy==1.24.3
pandas==2.0.3
geoip2==4.7.0
```

Install new dependencies:

```bash
docker compose exec event-collector pip install xgboost scikit-learn
```

### Step 4: Deploy enrichment_advanced.py

Copy the module to container:

```bash
cp enrichment_advanced.py services/event-collector/
```

### Step 5: Create ML Model Directory

```bash
mkdir -p volumes/ml-models
```

The model will be saved at: `/volumes/ml-models/xgb_anomaly_model.pkl`

### Step 6: Update ClickHouse Schema

Execute migration:

```bash
docker compose exec clickhouse clickhouse-client --database=iam < migration_v2_add_35_features.sql
```

Or manually in ClickHouse UI:

```
SELECT 'Login to ClickHouse UI -> Default database -> iam -> run_file()'
```

### Step 7: Backup and Replace main.py

```bash
# Backup
cp services/event-collector/main.py services/event-collector/main_v1_backup.py

# Copy new version
cp main_v2.py services/event-collector/main.py

# Or merge changes into existing main.py if you have custom modifications
```

### Step 8: Rebuild and Redeploy

```bash
# Rebuild image
docker compose build --no-cache event-collector

# Restart service
docker compose down
docker compose up -d event-collector

# Check logs
docker compose logs -f event-collector
```

## Configuration Details

### API Keys & Webhooks

#### IPQS API (VPN/Proxy Detection)
- Get key from: https://ipqualityscore.com/
- Used by: `detect_vpn()`, `detect_proxy()` in enrichment_advanced.py
- Accuracy: ~95% for VPN, ~85% for proxy
- Rate limit: 5000 req/month (free tier)

#### SIEM Webhook Integration
- Endpoint: Your SIEM's webhook URL
- Payload format: JSON with all 86 features
- Used by: `send_to_siem()` in Groupe 20
- Example: `http://splunk.local:8088/services/collector`

#### ML Model
- Type: XGBoost binary classifier (anomaly detection)
- Location: `/app/models/xgb_anomaly_model.pkl`
- Features: 20+ input features (extracted from event data)
- Output: Anomaly score (0-1, higher = more anomalous)
- Training: Historical 90 days of data (requires preparation)

### Thresholds & Classification

```yaml
VPN_DETECTION_THRESHOLD: 0.8      # IPQS confidence > 80%
PROXY_DETECTION_THRESHOLD: 0.8    # IPQS confidence > 80%
BOT_SCORE_THRESHOLD: 0.7          # Headless browser detection
IMPOSSIBLE_TRAVEL_SPEED_KMH: 900  # Max realistic travel speed
DORMANCY_DAYS: 30                 # Account inactivity threshold
ML_CONFIDENCE_THRESHOLD: 0.7      # High confidence anomaly flag

BLOCKED_COUNTRIES: ["IR", "KP", "SY"]        # Fully blocked
RESTRICTED_COUNTRIES: ["CN", "RU", "KR"]    # Flagged but allowed
PCI_SENSITIVE_APPS: ["finance", "admin"]    # Require MFA
HIPAA_SENSITIVE_APPS: ["hr"]                # Compliance level
```

## Features by Groupe

### Groupe 13: Advanced Context (8 features)

| Feature | Source | Calculation | Use Case |
|---------|--------|-------------|----------|
| `user_location_history` | ClickHouse history | Last 10 login locations | Baseline for travel detection |
| `is_impossible_travel` | Haversine formula | Distance / time > 900 km/h | Detect impossible travel |
| `distance_from_last_location_km` | GPS coordinates | Haversine distance | Geographic context |
| `is_vpn_detected` | IPQS API | IP reputation + behavior | Anonymity detection |
| `vpn_provider` | IPQS API | Service name lookup | Specific provider tracking |
| `is_proxy_detected` | IPQS API | Proxy fingerprinting | Proxy detection |
| `proxy_provider` | IPQS API | Provider identification | Track specific proxies |
| `http_x_forwarded_for` | HTTP headers | Multi-hop detection | Multi-layer proxy tracking |

### Groupe 14: Behavior (5 features)

| Feature | Source | Calculation | Risk Impact |
|---------|--------|-------------|-------------|
| `consecutive_failures` | Login history | Count before success | Password guessing detection |
| `time_since_last_login` | History timestamp | Minutes elapsed | Account usage baseline |
| `is_account_dormant` | 30+ day inactivity | Reactivation risk | Takeover post-dormancy |
| `login_frequency_deviation` | Statistical analysis | Z-score of frequency | Pattern deviation |
| `app_switching_count` | Lateral movement | App transitions in session | Lateral movement |

### Groupe 15: ML Anomaly (4 features)

| Feature | Model | Output | Threshold |
|---------|-------|--------|-----------|
| `ml_anomaly_score` | XGBoost | 0-1 probability | > 0.7 = high risk |
| `ml_feature_importance` | SHAP values | Top 10 features | For explainability |
| `is_ml_high_confidence` | Score stddev | 0/1 confidence flag | > 0.95 confidence |
| `ml_model_version` | Metadata | Version tag | v2.3.1 |

**ML Feature Vector (20 dimensions):**
- abuse_score, is_tor, is_vpn_detected, is_proxy_detected
- consecutive_failures, fails_1h, fails_24h, is_new_device
- is_night_login, is_weekend, app_sensitivity, geo_distance
- login_frequency_deviation, is_impossible_travel, mfa_success
- ua_entropy, session_age, lateral_movement, breach_flag, risk_score

### Groupe 16: MFA (4 features)

| Feature | Source | Values | Risk Edge Cases |
|---------|--------|--------|-----------------|
| `mfa_method_used` | Event payload | TOTP/SMS/EMAIL/PUSH | Bypass indicators |
| `mfa_response_time_secs` | Timestamp diff | -1 (N/A), 1-300 | Impossible response times |
| `mfa_success` | Event status | 0/1 | Repeated failures = attack |
| `mfa_attempts_before_success` | Counter | 1-5+ | Brute force indicator |

### Groupe 17: Security (4 features)

| Feature | Detection Method | Signals | Action |
|---------|------------------|---------|--------|
| `bot_score` | Headless browser, UA analysis | 0-1 | > 0.7 = block |
| `is_credential_stuffing` | Multiple IPs, same password patterns | List attacks | Rate limiting |
| `is_account_takeover` | Multi-signal (impossible travel + VPN + new device + MFA fails) | Combined scoring | Require MFA re-enrollment |
| `is_session_hijacking` | Same session ID, different device/IP/UA | Deviation detection | Rate limit / re-auth |

### Groupe 18: Predictive (2 features)

| Feature | Input | Output | Purpose |
|---------|-------|--------|---------|
| `risk_trend` | History variance | STABLE / INCREASING / DECREASING | Trend indication |
| `predicted_risk_next_login` | ML forecast | 0-100 score | Proactive alerting |

### Groupe 19: Compliance (3 features)

| Feature | Standard | Values | Action |
|---------|----------|--------|--------|
| `regulatory_classification` | Framework | PCI-DSS / HIPAA / GDPR / PII | Audit logging |
| `breach_flag` | HIBP + threat feeds | 0/1 | Track compromised accounts |
| `access_from_restricted_country` | Geo blocklist | 0/1 | Block or flag |

### Groupe 20: Integration (3 features)

| Feature | Destination | Format | Use |
|---------|-------------|--------|-----|
| `siem_alert_id` | External SIEM | UUID | Alert correlation |
| `external_threat_feed_match` | abuse.ch, malwaredomains | JSON array | Threat tracking |
| `darknet_market_mention` | Darknet monitors | 0/1 flag | Deep web monitoring |

## Testing

### Unit Tests

```python
# Test detection functions
from enrichment_advanced import detect_vpn, detect_proxy, detect_impossible_travel

# VPN Detection
assert detect_vpn("185.220.101.1") == (1, "TOR")  # TOR exit node
assert detect_vpn("185.220.102.1") == (0, "")     # Normal IP

# Impossible Travel
event = {
    "ip": "8.8.8.8",
    "geo_latitude": 40.7128, "geo_longitude": -74.0060,  # NYC
    "event_time": datetime.now()
}
assert detect_impossible_travel(event, [{
    "geo_latitude": 51.5074, "geo_longitude": -0.1278,   # London
    "event_time": datetime.now() - timedelta(minutes=30)
}]) == 1  # Impossible
```

### Integration Test

```bash
# Test event POST to /events endpoint
curl -X POST http://localhost:8088/events \
  -H "Content-Type: application/json" \
  -d '{
    "type": "LOGIN",
    "realm": "PFE-SSO",
    "clientId": "finance-client",
    "userId": "user123",
    "details": {"username": "john.doe"},
    "ipAddress": "185.220.101.1",
    "http_user_agent": "Mozilla/5.0...",
    "sessionId": "abc123xyz"
  }'

# Expected enrichment response includes:
# - is_vpn_detected: 1 (TOR)
# - ml_anomaly_score: 0.85
# - is_account_takeover_suspected: 1 (multi-signal trigger)
# - bot_score: 0.2 (normal browser)
```

### Dashboard Verification

Login to ClickHouse UI:
- http://localhost:8123

Run dashboard queries:

```sql
-- High risk logins (24h)
SELECT * FROM iam.v_high_risk_logins LIMIT 10;

-- Anomalies by user
SELECT * FROM iam.v_anomalies_by_user LIMIT 5;

-- Geographic anomalies
SELECT * FROM iam.v_geographic_anomalies LIMIT 10;

-- Threat patterns
SELECT * FROM iam.v_threat_patterns LIMIT 7;
```

## Migration Path

### Phase 1: Parallel Deployment (Day 1-2)
- Run main_v2.py on separate port (8089)
- Keep main.py on port 8088
- Route 10% of events to v2 for validation

### Phase 2: Validation (Day 3-5)
- Compare enrichment outputs
- Audit ClickHouse v2 table
- Test dashboard queries
- Validate ML model predictions

### Phase 3: Cutover (Day 6)
- Point all events to v2
- Archive v1 data
- Update Keycloak listener config
- Monitor for errors

### Phase 4: Optimization (Week 2)
- Fine-tune thresholds
- Train ML model on full dataset
- Optimize indexes
- Archive old tables

## Troubleshooting

### Issue: "enrichment_advanced module not found"

**Solution:**
```bash
docker compose exec event-collector ls -la enrichment_advanced.py
# If missing:
docker compose cp enrichment_advanced.py event-collector:/app/
docker compose restart event-collector
```

### Issue: "XGBoost model not found"

**Solution:**
```bash
# Create dummy model for testing (replace after ML training)
docker compose exec event-collector python -c "
import pickle
import xgboost as xgb
# Load/create model
model = xgb.DummyClassifier()
pickle.dump(model, open('/app/models/xgb_anomaly_model.pkl', 'wb'))
"
```

### Issue: "IPQS API key invalid"

**Solution:**
```bash
# Test API key
curl "https://api.ipqualityscore.com/api/json/ip/193.43.173.11?key=YOUR_KEY&format=json"
# Should return valid IP reputation data
```

### Issue: "ClickHouse table creation failed"

**Solution:**
```bash
# Delete old table
docker compose exec clickhouse clickhouse-client --database=iam --query "DROP TABLE login_events_v2"

# Re-run migration
docker compose exec clickhouse clickhouse-client --database=iam < migration_v2_add_35_features.sql
```

### Issue: "High memory usage in enrichment_advanced"

**Solution:**
- Increase container memory limit in docker-compose.yml
- Reduce history cache size (currently 10000 users)
- Use Redis for distributed caching (production)

## Performance Metrics

| Metric | Expected | Range |
|--------|----------|-------|
| Basic enrichment (51) | 150ms | 100-300ms |
| Advanced enrichment (35) | 300ms | 200-500ms |
| **Total event latency** | **450ms** | 300-800ms |
| ML model inference | 50ms | 30-100ms |
| External API calls (serial) | 200ms | 100-400ms |
| ClickHouse insert | 20ms | 10-50ms |

**Optimization Tips:**
1. Cache ML model in-memory (done)
2. Use thread pool for external API calls
3. Batch ClickHouse inserts (done in v2)
4. Enable Redis for distributed caching
5. Pre-fetch user history on anomaly detection

## Monitoring & Alerting

### Prometheus Metrics (to implement)

```python
from prometheus_client import Counter, Histogram, Gauge

# Counters
events_processed = Counter('events_processed_total', 'Total events')
anomalies_detected = Counter('anomalies_detected_total', 'Anomalies')

# Histograms
enrichment_duration = Histogram('enrichment_duration_seconds', 'Enrichment latency')
ml_anomaly_score = Histogram('ml_anomaly_score', 'ML scores')

# Gauges
high_risk_users_current = Gauge('high_risk_users', 'Current high-risk user count')
```

### Alert Rules (to setup)

```yaml
- alert: HighAnomalyRate
  expr: rate(anomalies_detected_total[5m]) > 10
  for: 5m
  annotations:
    summary: "{{ $value }} anomalies/min detected"

- alert: EnrichmentLatency
  expr: histogram_quantile(0.95, enrichment_duration_seconds) > 1.0
  for: 10m
  annotations:
    summary: "95th percentile enrichment latency > 1s"
```

## Next Steps

1. **ML Model Training**: Collect 90+ days of historical data and train XGBoost
2. **A/B Testing**: Compare v1 vs v2 feature detection accuracy
3. **SIEM Integration**: Connect to external SIEM for alert correlation
4. **Redis Migration**: Move from in-memory to Redis for production scale
5. **API Rate Limiting**: Implement exponential backoff for external APIs

---

**Questions?** Contact: security-team@company.com  
**Documentation**: See DOCUMENTATION_COMPLETE.txt  
**Deployment**: See GUIDE_DEPLOIEMENT.txt
