import { API_ENDPOINTS } from "./config.js";

const cache = new Map();

async function scanUrl(url) {
  if (!url || !/^https?:\/\//i.test(url)) {
    return {
      url,
      riskScore: 0,
      severity: "safe",
      isSafe: true,
      indicators: ["Browser-internal or unsupported URL"],
      recommendation: "No scan required for this page."
    };
  }

  if (cache.has(url)) return cache.get(url);

  try {
    const response = await fetch(API_ENDPOINTS.scanUrl, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      credentials: "include",
      body: JSON.stringify({ url })
    });

    if (!response.ok) throw new Error(`API returned ${response.status}`);
    const result = await response.json();
    cache.set(url, result);
    return result;
  } catch (error) {
    return {
      url,
      riskScore: null,
      severity: "unknown",
      isSafe: false,
      indicators: ["Unable to contact Innovex Security server"],
      recommendation: "Do not enter sensitive information until the URL can be verified.",
      error: error.message
    };
  }
}

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message?.type === "SCAN_URL") {
    scanUrl(message.url).then(sendResponse);
    return true;
  }
});

chrome.tabs.onUpdated.addListener(async (tabId, changeInfo, tab) => {
  if (changeInfo.status !== "loading" || !tab.url) return;
  const result = await scanUrl(tab.url);
  await chrome.tabs.sendMessage(tabId, { type: "SCAN_RESULT", result }).catch(() => {});
});
