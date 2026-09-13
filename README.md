# Innovex Security — SIH Part 2

Desktop/browser protection layer for Innovex Security. The extension watches normal web navigation, sends URLs to the extension scan API, shows the risk score in the popup, and blocks complacency with an in-page warning for high/critical results.

## Project structure

```text
extension/                         Chrome / Chromium Manifest V3 extension
├── background.js                  URL scanning service worker
├── config.js                      API origin + optional access key
├── content.js                     In-page warning renderer
├── popup/                         Extension popup UI
└── styles/                       Warning banner styles

server/                            Standalone extension scan API
└── app/api/scan/url/route.js      Heuristic + URLhaus analysis
```

## Why there is a separate API

The original Innovex web application's `/api/scan/url` route is tied to the web dashboard's authenticated Supabase session. A browser extension does not automatically have that dashboard session, so Part 2 uses `server/app/api/scan/url/route.js` as a small extension-facing API. The URLhaus key stays server-side.

## Run locally

### 1. Start the scan API

```bash
cd server
npm install
copy .env.example .env.local
npm run dev
```

On macOS/Linux, use `cp .env.example .env.local` instead of `copy`.

The API runs at `http://localhost:3000`.

### 2. Load the extension

Open Chrome/Edge and go to:

`chrome://extensions`

Turn on **Developer mode** → **Load unpacked** → select the repository's `extension` folder.

`extension/config.js` already points to `http://localhost:3000` for local development.

### 3. Optional URLhaus protection

Set `URLHAUS_AUTH_KEY` in `server/.env.local`. Without it, the heuristic engine still works, but URLhaus threat-intelligence checks are unavailable.

### 4. Optional extension access key

Set `EXTENSION_API_KEY` on the server and put the same value in `extension/config.js`. This is only an access-control/demo key; values embedded in a browser extension cannot be treated as confidential secrets.

## What the extension does

- Scans HTTP/HTTPS pages automatically during navigation.
- Checks HTTPS usage, IP-based hosts, punycode, excessive subdomains, suspicious security terms, long URLs, `@` in URLs, non-standard ports, and query-parameter volume.
- Optionally checks URLhaus for known malicious URLs.
- Shows score, severity, confidence, indicators, and recommendation in the popup.
- Shows an in-page warning for **High** and **Critical** results.
- Caches results briefly so a page does not get repeatedly scanned on every popup open.

## Deployment

Deploy `server/` as a normal Next.js application on Vercel or another Node-compatible host. Add the environment variables from `server/.env.example`, then replace `API_BASE_URL` in `extension/config.js` with the public scan API origin and reload the unpacked extension.

## SIH Part 2 architecture

```text
                 ┌──────────────────────────────┐
                 │   Chrome / Chromium Browser  │
                 └──────────────┬───────────────┘
                                │ page URL
                                ▼
                 ┌──────────────────────────────┐
                 │ Innovex MV3 Extension        │
                 │ Popup + Service Worker        │
                 │ + Content Warning Banner     │
                 └──────────────┬───────────────┘
                                │ POST /api/scan/url
                                ▼
                 ┌──────────────────────────────┐
                 │ Extension Scan API            │
                 │ Heuristic Analysis            │
                 └──────────────┬───────────────┘
                                │
                    ┌───────────┴───────────┐
                    ▼                       ▼
             URL Structure            URLhaus Intel
             Risk Signals             Known Threats
                    └───────────┬───────────┘
                                ▼
                    Risk Score + Recommendation
                                │
                  ┌─────────────┴─────────────┐
                  ▼                           ▼
             Popup Result              Page Warning
```
