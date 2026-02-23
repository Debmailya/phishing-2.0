# Database Schema

## organizations
- `id` (PK)
- `name` (unique)
- `api_key` (unique)
- `rate_limit_per_minute`
- `created_at`

## users
- `id` (PK)
- `email` (unique)
- `hashed_password`
- `role` (`admin|analyst|user`)
- `organization_id` (FK -> organizations.id)
- `is_active`

## threat_scans
- `id` (PK)
- `organization_id` (FK -> organizations.id)
- `submitted_url_hash` (SHA-256, no raw URL retention)
- `detected_brand`
- `risk_score`
- `verdict`
- `evidence` (JSON string)
- `created_at`
