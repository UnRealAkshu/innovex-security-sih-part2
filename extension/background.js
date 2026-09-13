import { API_ENDPOINTS, EXTENSION_API_KEY } from "./config.js";

const cache = new Map();
const tabSignals = new Map();
const CACHE_TTL_MS = 10 * 60 * 1000;

function unsupportedResult(url) {
  return {
    success: true,
    url,
    riskScore: 0,
    severity: "Low",
    confidence: 100,
    threatDetected: false,
    indicators: ["Browser-internal or unsupported URL"],
    recommendation: "No scan required for this page."
  };
}

function applyPageSignals(result, signals) {
  if (!signals || !result || result.riskScore == null) return result;

  let score = Number(result.riskScore) || 0;
  const indicators = Array.isArray(result.indicators) ? [...result.indicators] : [];
  const passwordFields = Number(signals.passwordFields) || 0;
  const emailFields = Number(signals.emailFields) || 0;
  const sensitiveFields = Number(signals.sensitiveFields) || 0;
  const externalFormTargets = Number(signals.externalFormTargets) || 0;
  const authWords = Array.isArray(signals.matchedAuthWords) ? signals.matchedAuthWords : [];

  if (signals.knownSecurityTestPage) {
    score = 100;
    indicators.push("Known safe AMTSO phishing-simulation test page detected.");
    indicators.push("This page is a security test, not a real malicious website.");
  }

  if (passwordFields > 0) {
    score += 15;
    indicators.push("The page contains a password input field.");
  }

  if (passwordFields > 0 && (emailFields > 0 || authWords.length > 0)) {
    score += 15;
    indicators.push("The page appears to collect login/account credentials.");
  }

  if (sensitiveFields > 0) {
    score += 15;
    indicators.push("The page contains a field associated with sensitive information.");
  }

  if (externalFormTargets > 0) {
    score += 25;
    indicators.push("A form submits data to an external origin.");
  }

  if (authWords.length >= 2 && passwordFields > 0) {
    score += 5;
    indicators.push("Multiple authentication-related terms appear alongside a password field.");
  }

  if (signals.hasPaymentLanguage && sensitiveFields > 0) {
    score += 15;
    indicators.push("Payment or billing language appears near sensitive input fields.");
  }

  if (signals.hasUrgencyLanguage && (passwordFields > 0 || sensitiveFields > 0)) {
    score += 15;
    indicators.push("Urgency language appears on a page requesting sensitive information.");
  }

  score = Math.min(100, Math.max(0, score));
  const severity = score >= 80 ? "Critical" : score >= 60 ? "High" : score >= 30 ? "Medium" : "Low";

  return {
    ...result,
    riskScore: score,
    severity,
    threatDetected: Boolean(result.threatDetected) || score >= 30,
    indicators: [...new Set(indicators)]
  };
}

function localAnalyze(url, signals = null) {
  let parsed;
  try {
    parsed = new URL(url);
  } catch {
    return unknownResult(url, "Invalid URL");
  }

  const protocol = parsed.protocol.replace(":", "").toLowerCase();
  const hostname = parsed.hostname.toLowerCase();
  const normalizedUrl = parsed.toString();
  const indicators = [];
  let riskScore = 0;

  if (protocol !== "https") {
    riskScore += 20;
    indicators.push("The URL does not use HTTPS.");
  }

  if (/^(?:\d{1,3}\.){3}\d{1,3}$/.test(hostname) || hostname.includes(":")) {
    riskScore += 25;
    indicators.push("The URL uses an IP address instead of a normal domain name.");
  }

  if (hostname.includes("xn--")) {
    riskScore += 20;
    indicators.push("The domain uses punycode, which can be used in lookalike-domain attacks.");
  }

  if (hostname.split(".").filter(Boolean).length >= 4) {
    riskScore += 10;
    indicators.push("The URL contains an unusually large number of subdomains.");
  }

  const suspiciousKeywords = [
    "login", "verify", "verification", "account", "secure", "security",
    "update", "password", "signin", "sign-in", "confirm", "bank", "wallet",
    "payment", "invoice", "unlock", "suspended", "urgent"
  ];
  const lower = normalizedUrl.toLowerCase();
  const matches = suspiciousKeywords.filter((keyword) => lower.includes(keyword));

  if (matches.length >= 3) {
    riskScore += 20;
    indicators.push(`Multiple security-sensitive terms detected: ${matches.slice(0, 6).join(", ")}.`);
  } else if (matches.length) {
    riskScore += 5;
    indicators.push(`Security-sensitive term detected: ${matches.slice(0, 4).join(", ")}.`);
  }

  if (normalizedUrl.length > 180) {
    riskScore += 10;
    indicators.push("The URL is unusually long.");
  }

  if (normalizedUrl.includes("@")) {
    riskScore += 20;
    indicators.push("The URL contains an @ symbol or embedded credential-like information.");
  }

  if (parsed.port && !["80", "443"].includes(parsed.port)) {
    riskScore += 15;
    indicators.push("The URL uses a non-standard network port.");
  }

  if ([...parsed.searchParams.keys()].length >= 5) {
    riskScore += 10;
    indicators.push("The URL contains many query parameters.");
  }

  const base = {
    success: true,
    mode: "local-fallback",
    url: normalizedUrl,
    riskScore: Math.min(100, Math.max(0, riskScore)),
    severity: "Low",
    confidence: 80,
    threatDetected: false,
    domain: hostname,
    protocol,
    analysisType: "Local heuristic + page signal fallback",
    indicators,
    recommendation: "The page appears relatively low risk based on available local checks."
  };

  const combined = applyPageSignals(base, signals);
  combined.confidence = Math.min(95, Math.max(70, 100 - Math.abs(50 - combined.riskScore)));
  combined.threatDetected = combined.riskScore >= 30;
  combined.indicators = combined.indicators.length
    ? combined.indicators
    : ["No suspicious URL or page-level indicators detected by local checks."];
  combined.recommendation = combined.knownSecurityTestPage || signals?.knownSecurityTestPage
    ? "Safe phishing-simulation page detected. This result confirms the Innovex warning pipeline is working."
    : combined.severity === "Critical"
      ? "Do not open this URL. Avoid entering credentials or sensitive information."
      : combined.severity === "High"
        ? "Avoid opening this URL until it has been independently verified."
        : combined.severity === "Medium"
          ? "Use caution and verify the page and source independently before entering sensitive information."
          : "The page appears relatively low risk based on available local checks.";

  return combined;
}

function unknownResult(url, message = "Unable to contact Innovex Security server") {
  return {
    success: false,
    url,
    riskScore: null,
    severity: "Unknown",
    confidence: null,
    threatDetected: false,
    indicators: [message],
    recommendation: "Do not enter sensitive information until the URL can be verified."
  };
}

function normalizeResult(url, result, signals = null) {
  const severity = result?.severity || "Unknown";
  const riskScore = Number.isFinite(result?.riskScore) ? result.riskScore : null;
  const normalized = {
    ...result,
    url: result?.url || url,
    riskScore,
    severity,
    indicators: Array.isArray(result?.indicators) ? result.indicators : [],
    recommendation: result?.recommendation || "Review this URL carefully before continuing."
  };

  return applyPageSignals(normalized, signals);
}

async function scanUrl(url, force = false, signals = null) {
  if (!url || !/^https?:\/\//i.test(url)) return unsupportedResult(url);

  const cacheKey = `${url}|${JSON.stringify(signals || {})}`;
  const cached = cache.get(cacheKey);
  if (!force && cached && Date.now() - cached.timestamp < CACHE_TTL_MS) return cached.result;

  try {
    const headers = { "Content-Type": "application/json" };
    if (EXTENSION_API_KEY) headers["X-Innovex-Extension-Key"] = EXTENSION_API_KEY;

    const response = await fetch(API_ENDPOINTS.scanUrl, {
      method: "POST",
      headers,
      body: JSON.stringify({ url, pageSignals: signals }),
      cache: "no-store"
    });

    const data = await response.json().catch(() => ({}));
    if (!response.ok || data?.success === false) throw new Error(data?.error || `API returned ${response.status}`);

    const result = normalizeResult(url, data, signals);
    cache.set(cacheKey, { timestamp: Date.now(), result });
    return result;
  } catch (error) {
    console.warn("Innovex API scan failed; using local fallback:", error);
    const fallback = localAnalyze(url, signals);
    cache.set(cacheKey, { timestamp: Date.now(), result: fallback });
    return fallback;
  }
}

async function notifyTab(tabId, result) {
  if (!tabId || !result) return;
  await chrome.tabs.sendMessage(tabId, { type: "SCAN_RESULT", result }).catch(() => {});
}

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message?.type === "PAGE_SIGNALS") {
    const tabId = sender.tab?.id;
    if (tabId) {
      tabSignals.set(tabId, { url: message.url, signals: message.signals });
      scanUrl(message.url, true, message.signals).then((result) => notifyTab(tabId, result));
    }
    return;
  }

  if (message?.type === "SCAN_URL") {
    const tabId = sender.tab?.id;
    const stored = tabId ? tabSignals.get(tabId) : null;
    scanUrl(message.url, Boolean(message.force), stored?.url === message.url ? stored.signals : null).then(sendResponse);
    return true;
  }
});

chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
  if (changeInfo.status !== "loading" || !tab?.url || !/^https?:\/\//i.test(tab.url)) return;
  tabSignals.delete(tabId);

  scanUrl(tab.url).then(async (result) => {
    await notifyTab(tabId, result);
    setTimeout(() => notifyTab(tabId, result), 700);
  });
});

chrome.tabs.onRemoved.addListener((tabId) => tabSignals.delete(tabId));
