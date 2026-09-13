import { API_ENDPOINTS, EXTENSION_API_KEY } from "./config.js";

const cache = new Map();
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

function localAnalyze(url) {
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

  riskScore = Math.min(100, Math.max(0, riskScore));
  const severity = riskScore >= 80 ? "Critical" : riskScore >= 60 ? "High" : riskScore >= 30 ? "Medium" : "Low";
  const recommendation = severity === "Critical"
    ? "Do not open this URL. Avoid entering credentials or sensitive information."
    : severity === "High"
      ? "Avoid opening this URL until it has been independently verified."
      : severity === "Medium"
        ? "Use caution and verify the source independently before continuing."
        : "The URL appears relatively low risk based on local heuristic checks.";

  return {
    success: true,
    mode: "local-fallback",
    url: normalizedUrl,
    riskScore,
    severity,
    confidence: Math.min(95, Math.max(70, 100 - Math.abs(50 - riskScore))),
    threatDetected: riskScore >= 30,
    domain: hostname,
    protocol,
    analysisType: "Local heuristic fallback",
    indicators: indicators.length ? indicators : ["No suspicious URL indicators detected by local checks."],
    recommendation
  };
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

function normalizeResult(url, result) {
  const severity = result?.severity || "Unknown";
  const riskScore = Number.isFinite(result?.riskScore) ? result.riskScore : null;

  return {
    ...result,
    url: result?.url || url,
    riskScore,
    severity,
    indicators: Array.isArray(result?.indicators) ? result.indicators : [],
    recommendation: result?.recommendation || "Review this URL carefully before continuing."
  };
}

async function scanUrl(url, force = false) {
  if (!url || !/^https?:\/\//i.test(url)) return unsupportedResult(url);

  const cached = cache.get(url);
  if (!force && cached && Date.now() - cached.timestamp < CACHE_TTL_MS) {
    return cached.result;
  }

  try {
    const headers = { "Content-Type": "application/json" };
    if (EXTENSION_API_KEY) headers["X-Innovex-Extension-Key"] = EXTENSION_API_KEY;

    const response = await fetch(API_ENDPOINTS.scanUrl, {
      method: "POST",
      headers,
      body: JSON.stringify({ url }),
      cache: "no-store"
    });

    const data = await response.json().catch(() => ({}));
    if (!response.ok || data?.success === false) {
      throw new Error(data?.error || `API returned ${response.status}`);
    }

    const result = normalizeResult(url, data);
    cache.set(url, { timestamp: Date.now(), result });
    return result;
  } catch (error) {
    console.warn("Innovex API scan failed; using local fallback:", error);
    const fallback = localAnalyze(url);
    cache.set(url, { timestamp: Date.now(), result: fallback });
    return fallback;
  }
}

async function notifyTab(tabId, result) {
  if (!tabId || !result) return;
  await chrome.tabs.sendMessage(tabId, { type: "SCAN_RESULT", result }).catch(() => {});
}

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message?.type === "SCAN_URL") {
    scanUrl(message.url, Boolean(message.force)).then(sendResponse);
    return true;
  }
});

chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
  if (changeInfo.status !== "loading" || !tab?.url || !/^https?:\/\//i.test(tab.url)) return;

  scanUrl(tab.url).then(async (result) => {
    await notifyTab(tabId, result);
    setTimeout(() => notifyTab(tabId, result), 700);
  });
});
