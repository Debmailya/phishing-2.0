# API Documentation (v1)

## Auth
- `POST /api/v1/auth/login` -> issue JWT token.
- `POST /api/v1/auth/organizations/{id}/api-key` -> rotate org API key (admin only).
- `GET /api/v1/auth/me` -> current user profile.

## Scanning
- `POST /api/v1/scans`
  - Header: `X-API-Key: pg_...`
  - Body: `{ "url": "https://example.com/login" }`
  - Returns risk score, verdict, reasons, and detected brand.

## Analytics
- `GET /api/v1/analytics/overview` -> 30-day threat summary.
- `POST /api/v1/analytics/retrain` -> trigger model retraining queue.

## Security Constraints
- SSRF-protected hosts are blocked.
- URL hash retained in logs/storage instead of raw sensitive target.
- Rate limiting enforced per organization.
