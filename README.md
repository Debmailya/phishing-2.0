# PhishGuard AI Enterprise

PhishGuard AI Enterprise is a multi-tenant anti-phishing SaaS platform designed for financial institutions and e-commerce companies. It evolves a basic URL checker into an operational cybersecurity product with tenant isolation, API security, threat analytics, and machine-learning driven detections.

## Core Capabilities
- Multi-tenant architecture for MSP/SOC and enterprise customers.
- JWT authentication + role-based access (`admin`, `analyst`, `user`).
- Organization API keys with rotation endpoint.
- Redis-backed per-organization rate limiting.
- Security-first scan pipeline: WHOIS age, DNS checks, SSL validation, homograph and lookalike brand detection, blacklist checks, Safe Browsing integration.
- ML lifecycle scripts: training, confusion matrix, feature importance, SHAP explainability.
- SOC dashboard for threat trends and attacked-brand monitoring.
- Dockerized deployment with Nginx reverse proxy and CI workflow.

## Production Folder Structure

- `backend/` FastAPI app, security middleware, APIs, services, ML assets.
- `frontend/` React SOC dashboard.
- `docs/` Architecture, API guide, schema, and enterprise scenario docs.
- `infra/` Nginx configuration and infra-facing assets.
- `.github/workflows/` CI/CD starter pipeline.

## Quick Start
```bash
cp .env.example .env
docker compose up --build
```

Access:
- API: `http://localhost/api/v1`
- Dashboard: `http://localhost/`

## Enterprise Workflow Example
A digital bank submits outbound URLs to `/api/v1/scans` before rendering them to customers. URLs with malicious verdicts are blocked inline, then surfaced in the dashboard for analyst response and compliance reporting.

See `docs/enterprise-scenario.md` for the full sequence.

## Deployment Notes
- Replace local Postgres/Redis with managed cloud offerings.
- Enable Let's Encrypt with Certbot or cloud-native TLS certificates.
- Move model training to scheduled jobs or dedicated worker queues.
- Ship logs to SIEM (Splunk/ELK/Datadog) using structured JSON logging.
