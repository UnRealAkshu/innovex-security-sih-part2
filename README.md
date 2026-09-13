# Innovex Security — SIH Part 2

Browser-based phishing and malicious-link protection for desktop users.

## What this part adds

- Chrome / Chromium Manifest V3 extension
- Automatic scanning of the active tab URL
- Popup with risk score, severity, indicators and recommendation
- In-page warning banner for high-risk and critical URLs
- Secure connection to the Innovex Security backend
- No threat-intelligence secrets shipped inside the extension

## Architecture

```text
Browser Extension
├── Popup UI
├── Background Service Worker
├── Content Script
└── Local Storage
        |
        v
Innovex Security API
        |
        +-- Heuristic URL analysis
        +-- URLhaus threat intelligence
        +-- Supabase scan history
```

## Setup

1. Deploy the existing Innovex Security web app/backend.
2. Set `API_BASE_URL` in `extension/config.js` to the deployed API origin.
3. Open `chrome://extensions`.
4. Enable **Developer mode**.
5. Choose **Load unpacked** and select the `extension` directory.

## Development notes

The extension does not contain the URLhaus authentication key. URLhaus access remains on the server side, matching the security model of the original Innovex Security application.

## SIH Part 2 direction

This repository is the desktop/browser protection layer built on top of the original Innovex Security prototype. The browser extension detects suspicious navigation, explains risk, and warns users before sensitive actions.
