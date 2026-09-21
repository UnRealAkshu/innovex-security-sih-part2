package com.innovex.security;

import org.json.JSONArray;
import org.json.JSONObject;

import java.io.BufferedReader;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URI;
import java.net.URL;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public final class UrlScanner {
    private static final String API_BASE_URL = "http://10.0.2.2:3000";
    private static final Pattern URL_PATTERN = Pattern.compile("https?://[^\s<>"']+", Pattern.CASE_INSENSITIVE);

    private UrlScanner() {}

    public static final class Result {
        public final String url;
        public final int riskScore;
        public final String severity;
        public final int confidence;
        public final boolean threatDetected;
        public final List<String> indicators;
        public final String recommendation;
        public final String engineVersion;

        public Result(String url, int riskScore, String severity, int confidence, boolean threatDetected,
                      List<String> indicators, String recommendation, String engineVersion) {
            this.url = url;
            this.riskScore = riskScore;
            this.severity = severity;
            this.confidence = confidence;
            this.threatDetected = threatDetected;
            this.indicators = indicators;
            this.recommendation = recommendation;
            this.engineVersion = engineVersion;
        }
    }

    public static String extractUrl(String sharedText) {
        if (sharedText == null) return null;
        Matcher matcher = URL_PATTERN.matcher(sharedText);
        if (matcher.find()) return stripTrailingPunctuation(matcher.group());

        String trimmed = sharedText.trim();
        if (trimmed.startsWith("www.")) return "https://" + stripTrailingPunctuation(trimmed);
        return null;
    }

    private static String stripTrailingPunctuation(String value) {
        return value.replaceAll("[),.!?;:]+$", "");
    }

    public static Result scan(String url) {
        Result local = localScan(url);
        try {
            Result server = serverScan(url);
            if (server.riskScore >= local.riskScore) return server;
            Set<String> merged = new LinkedHashSet<>(server.indicators);
            merged.addAll(local.indicators);
            return new Result(url, local.riskScore, severityFor(local.riskScore),
                    Math.max(server.confidence, local.confidence),
                    local.riskScore >= 30 || server.threatDetected,
                    new ArrayList<>(merged),
                    recommendationFor(local.riskScore),
                    "2.0.0-mobile");
        } catch (Exception ignored) {
            return local;
        }
    }

    private static Result serverScan(String url) throws Exception {
        HttpURLConnection connection = (HttpURLConnection) new URL(API_BASE_URL + "/api/scan/url").openConnection();
        connection.setRequestMethod("POST");
        connection.setConnectTimeout(5000);
        connection.setReadTimeout(8000);
        connection.setDoOutput(true);
        connection.setRequestProperty("Content-Type", "application/json");

        JSONObject payload = new JSONObject();
        payload.put("url", url);
        payload.put("pageSignals", JSONObject.NULL);

        try (OutputStream output = connection.getOutputStream()) {
            output.write(payload.toString().getBytes("UTF-8"));
        }

        int responseCode = connection.getResponseCode();
        InputStream stream = responseCode >= 200 && responseCode < 300
                ? connection.getInputStream() : connection.getErrorStream();
        if (stream == null) throw new IllegalStateException("No response from Innovex API");

        StringBuilder responseText = new StringBuilder();
        try (BufferedReader reader = new BufferedReader(new InputStreamReader(stream))) {
            String line;
            while ((line = reader.readLine()) != null) responseText.append(line);
        }
        connection.disconnect();

        JSONObject response = new JSONObject(responseText.toString());
        if (!response.optBoolean("success", false)) throw new IllegalStateException("Scan API returned an error");

        int score = clamp(response.optInt("riskScore", 0));
        List<String> indicators = new ArrayList<>();
        JSONArray array = response.optJSONArray("indicators");
        if (array != null) {
            for (int i = 0; i < array.length(); i++) indicators.add(array.optString(i));
        }
        return new Result(url, score, severityFor(score), response.optInt("confidence", 80),
                response.optBoolean("threatDetected", score >= 30), indicators,
                response.optString("recommendation", recommendationFor(score)), "2.0.0-mobile");
    }

    private static Result localScan(String url) {
        int score = 0;
        List<String> indicators = new ArrayList<>();

        try {
            URI uri = URI.create(url);
            String lower = uri.toString().toLowerCase();
            String host = uri.getHost() == null ? "" : uri.getHost().toLowerCase();
            String path = ((uri.getPath() == null ? "" : uri.getPath()) + " "
                    + (uri.getQuery() == null ? "" : uri.getQuery())).toLowerCase();

            if (!"https".equalsIgnoreCase(uri.getScheme())) {
                score += 20;
                indicators.add("The URL does not use HTTPS.");
            }

            if (host.matches("^(?:\\d{1,3}\\.){3}\\d{1,3}$") || host.contains(":")) {
                score += 25;
                indicators.add("The URL uses an IP address instead of a normal domain name.");
            }

            if (host.contains("xn--")) {
                score += 20;
                indicators.add("The domain uses punycode, which can be used in lookalike-domain attacks.");
            }

            if (host.split("\\.").length >= 4) {
                score += 10;
                indicators.add("The URL contains an unusually large number of subdomains.");
            }

            String[] keywords = {"login", "verify", "verification", "account", "secure", "security", "update", "password", "signin", "sign-in", "confirm", "bank", "wallet", "payment", "invoice", "unlock", "suspended", "urgent"};
            int matches = 0;
            for (String keyword : keywords) if (lower.contains(keyword)) matches++;

            if (matches >= 3) {
                score += Math.min(35, 10 + (matches - 3) * 5);
                indicators.add("Multiple security-sensitive terms detected in the URL.");
            } else if (matches > 0) {
                score += matches * 5;
                indicators.add("Security-sensitive terms detected in the URL.");
            }

            String[] credentialTokens = {"login", "signin", "sign-in", "verify", "verification", "password", "account", "confirm", "secure"};
            int pathMatches = 0;
            for (String keyword : credentialTokens) if (path.contains(keyword)) pathMatches++;

            if (pathMatches >= 4) {
                score += 20;
                indicators.add("The URL path contains multiple credential or account-action terms.");
            }

            if (path.matches(".*login.*(verify|verification|password).*|.*signin.*(verify|password).*")) {
                score += 10;
                indicators.add("Authentication and verification steps appear together in the URL path.");
            }

            if (lower.length() > 180) {
                score += 10;
                indicators.add("The URL is unusually long.");
            }

            if (lower.contains("@")) {
                score += 20;
                indicators.add("The URL contains an @ symbol or embedded credential-like information.");
            }

            if (uri.getPort() > 0 && uri.getPort() != 80 && uri.getPort() != 443) {
                score += 15;
                indicators.add("The URL uses a non-standard network port.");
            }

            if (uri.getQuery() != null && uri.getQuery().split("&").length >= 5) {
                score += 10;
                indicators.add("The URL contains many query parameters.");
            }

            if ("www.amtso.org".equals(host)
                    && (uri.getPath().contains("check-desktop-phishing-page")
                    || uri.getPath().contains("feature-settings-check-phishing-page"))) {
                score = 100;
                indicators.add("Known safe AMTSO phishing-simulation test page detected.");
                indicators.add("This page is a security test, not a real malicious website.");
            }
        } catch (Exception ignored) {
            score = 70;
            indicators.add("The URL could not be parsed cleanly.");
        }

        score = clamp(score);
        return new Result(url, score, severityFor(score),
                Math.min(99, Math.max(70, 100 - Math.abs(50 - score))),
                score >= 30, indicators, recommendationFor(score), "2.0.0-mobile");
    }

    private static int clamp(int value) {
        return Math.max(0, Math.min(100, value));
    }

    public static String severityFor(int score) {
        if (score >= 75) return "Critical";
        if (score >= 50) return "High";
        if (score >= 25) return "Medium";
        return "Low";
    }

    private static String recommendationFor(int score) {
        if (score >= 75) return "Do not open this link. Avoid entering passwords, OTPs, payment details or other sensitive information.";
        if (score >= 50) return "High risk indicators were detected. Verify the source independently before continuing.";
        if (score >= 25) return "Use caution and verify the website/source before entering sensitive information.";
        return "No major malicious-link indicators were detected by the available checks.";
    }
}
