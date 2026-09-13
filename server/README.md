# Innovex Security — Extension Scan API

This folder contains the browser-extension backend. It exposes `POST /api/scan/url` without requiring the main Innovex web-app login session.

## Local run

```bash
cd server
npm install
# create .env.local from .env.example and set URLHAUS_AUTH_KEY when available
npm run dev
```

The API will be available at `http://localhost:3000`.

## Request

```json
{
  "url": "https://example.com"
}
```

## Response

The response includes `riskScore`, `severity`, `confidence`, `threatDetected`, `indicators`, `recommendation`, and URLhaus threat-intelligence details.

## Deployment

Deploy the `server` directory as a Next.js app on Vercel or another Node-compatible host. Add the variables from `.env.example` in the hosting provider. Then update `extension/config.js` with the deployed API origin.

The original Innovex web application keeps its authenticated `/api/scan/url` route. This server exists specifically so the extension does not depend on browser cookies from the web dashboard.
