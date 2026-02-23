# PhishGuard AI Enterprise Architecture

## Microservices Layout
- **API Gateway (FastAPI)**: JWT auth, tenant enforcement, RBAC, API key controls.
- **Detection Service**: URL reputation, WHOIS, DNS, SSL, brand spoofing, homograph checks.
- **Threat Intel Integrations**: Google Safe Browsing and blacklist feeds.
- **ML Service**: Feature extraction, model scoring, retraining pipeline.
- **SOC Dashboard (React)**: Analytics, trends, attacked brands, reporting UI.
- **Data Services**: PostgreSQL for tenant + scan data, Redis for rate limiting and queueing.

## Multi-Tenant Security Controls
- Organization-scoped API keys and user ownership.
- Per-organization rate limits with Redis token bucket windows.
- Role model:
  - Admin: tenant and key management, retraining.
  - Analyst: investigation + retraining trigger.
  - User: scan submission and read-only stats.

## Deployment Pattern
- Nginx reverse proxy handles ingress and routes `/api/*` to FastAPI.
- TLS termination via Let's Encrypt (production Certbot automation).
- Containers deployable to ECS/Fargate, GKE, or AKS with managed Postgres + Redis.
