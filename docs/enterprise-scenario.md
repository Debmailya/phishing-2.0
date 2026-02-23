# Enterprise Scenario: Digital Banking Protection

A regional digital bank uses PhishGuard AI Enterprise to secure customer login and payment domains.

1. Fraud intelligence team registers bank tenant and provisions API key.
2. Mobile banking app sends every external payment link to `/api/v1/scans` before redirecting users.
3. Detection engine flags lookalike domains (`paypa1-secure-login.com`) using brand impersonation + homograph checks.
4. URLs with high-risk scores are blocked immediately and sent to SOC dashboard.
5. Analysts review daily/weekly trends and export reports to compliance teams.
6. Weekly retraining improves model precision based on newly confirmed phishing domains.
