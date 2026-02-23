# PhishGuard AI

PhishGuard AI is a production-style cybersecurity web application that performs real-time phishing URL analysis and presents explainable threat intelligence.

## Features

- Real-time URL scanning API (`POST /api/scan`)
- Binary prediction: **Phishing** or **Legitimate**
- Confidence scores for both classes
- Explainable reasons for each risk decision
- Threat level mapping: Low / Medium / High / Critical
- Responsive, modern UI suitable for SaaS presentation
- SEO readiness (`robots.txt`, `sitemap.xml`, canonical metadata)
- Security hardening with `helmet` and rate limiting

## Quick Start

```bash
npm install
npm run dev
```

Open `http://localhost:3000`.

## Production Run

```bash
npm install --omit=dev
npm start
```

## Testing

```bash
npm test
```

## API Example

```bash
curl -X POST http://localhost:3000/api/scan \
  -H 'Content-Type: application/json' \
  -d '{"url":"https://example.com"}'
```

Response shape:

```json
{
  "scannedUrl": "https://example.com/",
  "domain": "example.com",
  "prediction": "Legitimate",
  "threatLevel": "Low",
  "confidence": {
    "phishing": 12,
    "legitimate": 88
  },
  "reasons": ["No strong phishing signals detected by the AI risk engine."],
  "analyzedAt": "2026-01-01T12:00:00.000Z"
}
```
