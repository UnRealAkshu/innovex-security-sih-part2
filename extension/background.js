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
    console.warn("Innovex extension scan failed:", error);
    return unknownResult(url, error?.message || "Unable to contact Innovex Security server");
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
    // The content script can race the first navigation event, so notify now and once again shortly after.
    await notifyTab(tabId, result);
    setTimeout(() => notifyTab(tabId, result), 700);
  });
});
