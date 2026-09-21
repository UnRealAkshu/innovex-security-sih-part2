# Innovex Security Mobile — Share to Scan (Android)

This is the Mode 2 mobile experience for Innovex Security.

## User flow

WhatsApp / Telegram / Chrome / any app → Share → Innovex Security → automatic URL scan → Low / Medium / High / Critical → Open or Go Back.

The Android activity registers for ACTION_SEND with text/plain, which makes Innovex available in the system share sheet for shared text/URLs.

## Run locally

1. Open mobile/android in Android Studio.
2. Run the app on an Android emulator or phone.
3. The app uses http://10.0.2.2:3000 for the Innovex scan API when running in an Android emulator.
4. For a physical device, change API_BASE_URL in UrlScanner.java to the LAN address of the machine running the server, for example http://192.168.1.10:3000.
5. Start the Innovex server from server/ with npm install and npm run dev.

The mobile app includes a local heuristic fallback, so it can still produce a risk score when the API is unavailable.

## Test

From Chrome: open a URL → Share → Innovex Security.

For a synthetic elevated-risk test, share:

http://example.com/login/verify/account/password/secure/update/confirm/bank/payment/wallet?user=1&verify=2&password=3&account=4&secure=5&token=6


## Real-time protection

1. Message Protection: an Android NotificationListenerService inspects notification text for HTTP(S) URLs and runs the Innovex URL scanner. Medium/High/Critical results generate an Innovex warning notification. Android requires the user to explicitly grant notification access.
2. Web Shield: Innovex registers as an HTTP/HTTPS browser handler and can request the Android browser role. Links that launch the system browser can be intercepted, scanned, and shown with Low/Medium/High/Critical risk before Innovex hands them to an external browser.
3. Share to Scan: the explicit WhatsApp/Telegram/Chrome → Share → Innovex flow remains available.

The Web Shield intentionally avoids AccessibilityService. It protects links routed through Android's browser handler; apps that keep URLs inside a private in-app WebView do not automatically route through Innovex.

### Emulator test flow

- Run Pixel 7 API 35.
- Open Innovex and tap Enable Message Protection; enable Innovex Message Protection in Android notification-access settings.
- Tap Enable Web Shield and allow Innovex to become the default browser when Android offers the browser-role dialog.
- Test a suspicious URL from Chrome or another app that launches an external browser.
