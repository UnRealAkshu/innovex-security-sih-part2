import { API_ENDPOINTS, EXTENSION_API_KEY } from "./config.js";

const cache = new Map();
const tabSignals = new Map();
const CACHE_TTL_MS = 10 * 60 * 1000;

function unsupportedResult(url) {
  return { success: true, url, riskScore: 0, severity: "Low", confidence: 100, threatDetected: false, indicators: ["Browser-internal or unsupported URL"], recommendation: "No scan required for this page.", engineVersion: "2.0.0" };
}

function localUrlScore(url) {
  let parsed;
  try { parsed = new URL(url); } catch { return { score: 0, indicators: [] }; }
  const lower = parsed.toString().toLowerCase();
  const indicators = [];
  let score = 0;

  if (parsed.protocol !== "https:") { score += 20; indicators.push("The URL does not use HTTPS."); }
  if (/^(?:\d{1,3}\.){3}\d{1,3}$/.test(parsed.hostname) || parsed.hostname.includes(":")) { score += 25; indicators.push("The URL uses an IP address instead of a normal domain name."); }
  if (parsed.hostname.includes("xn--")) { score += 20; indicators.push("The domain uses punycode, which can be used in lookalike-domain attacks."); }
  if (parsed.hostname.split(".").filter(Boolean).length >= 4) { score += 10; indicators.push("The URL contains an unusually large number of subdomains."); }

  const keywords = ["login", "verify", "verification", "account", "secure", "security", "update", "password", "signin", "sign-in", "confirm", "bank", "wallet", "payment", "invoice", "unlock", "suspended", "urgent"];
  const matches = [...new Set(keywords.filter((k) => lower.includes(k)))];
  if (matches.length) {
    const points = matches.length >= 3 ? Math.min(35, 10 + (matches.length - 3) * 5) : matches.length * 5;
    score += points;
    indicators.push(`${matches.length >= 3 ? "Multiple" : "Security-sensitive"} terms detected: ${matches.slice(0, 8).join(", ")}.`);
  }

  const path = `${parsed.pathname} ${parsed.search}`.toLowerCase();
  const credentialTokens = ["login", "signin", "sign-in", "verify", "verification", "password", "account", "confirm", "secure"];
  const pathMatches = credentialTokens.filter((k) => path.includes(k));
  if (pathMatches.length >= 4) { score += 20; indicators.push("The URL path contains multiple credential or account-action terms."); }
  if (/login.*(verify|verification|password)|signin.*(verify|password)/i.test(path)) { score += 10; indicators.push("Authentication and verification steps appear together in the URL path."); }

  if (lower.length > 180) { score += 10; indicators.push("The URL is unusually long."); }
  if (lower.includes("@")) { score += 20; indicators.push("The URL contains an @ symbol or embedded credential-like information."); }
  if (parsed.port && !["80", "443"].includes(parsed.port)) { score += 15; indicators.push("The URL uses a non-standard network port."); }
  if ([...parsed.searchParams.keys()].length >= 5) { score += 10; indicators.push("The URL contains many query parameters."); }

  return { score: Math.min(100, score), indicators };
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

  if (signals.knownSecurityTestPage) { score = 100; indicators.push("Known safe AMTSO phishing-simulation test page detected."); indicators.push("This page is a security test, not a real malicious website."); }
  if (passwordFields > 0) { score += 15; indicators.push("The page contains a password input field."); }
  if (passwordFields > 0 && (emailFields > 0 || authWords.length > 0)) { score += 15; indicators.push("The page appears to collect login/account credentials."); }
  if (sensitiveFields > 0) { score += 15; indicators.push("The page contains a field associated with sensitive information."); }
  if (externalFormTargets > 0) { score += 25; indicators.push("A form submits data to an external origin."); }
  if (authWords.length >= 2 && passwordFields > 0) { score += 5; indicators.push("Multiple authentication-related terms appear alongside a password field."); }
  if (signals.hasPaymentLanguage && sensitiveFields > 0) { score += 15; indicators.push("Payment or billing language appears near sensitive input fields."); }
  if (signals.hasUrgencyLanguage && (passwordFields > 0 || sensitiveFields > 0)) { score += 15; indicators.push("Urgency language appears on a page requesting sensitive information."); }

  score = Math.min(100, score);
  return { ...result, riskScore: score, severity: score >= 80 ? "Critical" : score >= 60 ? "High" : score >= 30 ? "Medium" : "Low", threatDetected: Boolean(result.threatDetected) || score >= 30, indicators: [...new Set(indicators)] };
}

function localAnalyze(url, signals = null) {
  const base = localUrlScore(url);
  const result = { success: true, mode: "local-baseline", url, riskScore: base.score, severity: "Low", confidence: 90, threatDetected: base.score >= 30, indicators: [...base.indicators], recommendation: "The page appears relatively low risk based on available local checks.", engineVersion: "2.0.0" };
  const combined = applyPageSignals(result, signals);
  combined.confidence = Math.min(99, Math.max(70, 100 - Math.abs(50 - combined.riskScore)));
  combined.threatDetected = combined.riskScore >= 30;
  combined.recommendation = combined.severity === "Critical" ? "Do not open this URL. Avoid entering credentials or sensitive information." : combined.severity === "High" ? "Avoid opening this URL until it has been independently verified. Do not enter passwords or payment information." : combined.severity === "Medium" ? "Use caution and verify the page and source independently before entering sensitive information." : "The page appears relatively low risk based on available local checks.";
  return combined;
}

function unknownResult(url, message) { return { success: false, url, riskScore: null, severity: "Unknown", confidence: null, threatDetected: false, indicators: [message || "Unable to contact Innovex Security server"], recommendation: "Do not enter sensitive information until the URL can be verified.", engineVersion: "2.0.0" }; }

async function scanUrl(url, force = false, signals = null) {
  if (!url || !/^https?:\/\//i.test(url)) return unsupportedResult(url);
  const cacheKey = `${url}|${JSON.stringify(signals || {})}`;
  const cached = cache.get(cacheKey);
  if (!force && cached && Date.now() - cached.timestamp < CACHE_TTL_MS) return cached.result;

  const local = localAnalyze(url, signals);
  try {
    const headers = { "Content-Type": "application/json" };
    if (EXTENSION_API_KEY) headers["X-Innovex-Extension-Key"] = EXTENSION_API_KEY;
    const response = await fetch(API_ENDPOINTS.scanUrl, { method: "POST", headers, body: JSON.stringify({ url, pageSignals: signals }), cache: "no-store" });
    const data = await response.json().catch(() => ({}));
    if (!response.ok || data?.success === false) throw new Error(data?.error || `API returned ${response.status}`);

    let result = { ...data, url: data?.url || url, engineVersion: "2.0.0" };
    result = applyPageSignals(result, signals);
    if (local.riskScore > (Number(result.riskScore) || 0)) {
      result = { ...result, riskScore: local.riskScore, severity: local.severity, threatDetected: local.threatDetected, indicators: [...new Set([...(result.indicators || []), ...local.indicators])] };
    }
    cache.set(cacheKey, { timestamp: Date.now(), result });
    return result;
  } catch (error) {
    console.warn("Innovex API scan failed; using local baseline:", error);
    cache.set(cacheKey, { timestamp: Date.now(), result: local });
    return local;
  }
}

async function notifyTab(tabId, result) { if (tabId && result) await chrome.tabs.sendMessage(tabId, { type: "SCAN_RESULT", result }).catch(() => {}); }

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message?.type === "PAGE_SIGNALS") {
    const tabId = sender.tab?.id;
    if (tabId) { tabSignals.set(tabId, { url: message.url, signals: message.signals }); scanUrl(message.url, true, message.signals).then((result) => notifyTab(tabId, result)); }
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
  scanUrl(tab.url).then(async (result) => { await notifyTab(tabId, result); setTimeout(() => notifyTab(tabId, result), 700); });
});
chrome.tabs.onRemoved.addListener((tabId) => tabSignals.delete(tabId));
