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
