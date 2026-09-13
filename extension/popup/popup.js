const state = document.querySelector("#state");
const resultBox = document.querySelector("#result");
const score = document.querySelector("#score");
const severity = document.querySelector("#severity");
const indicators = document.querySelector("#indicators");
const recommendation = document.querySelector("#recommendation");
const rescanButton = document.querySelector("#rescan");

function severityFromScore(value) {
  if (!Number.isFinite(value)) return "Unknown";
  if (value >= 75) return "Critical";
  if (value >= 50) return "High";
  if (value >= 25) return "Medium";
  return "Low";
}

function renderResult(data) {
  state.hidden = true;
  resultBox.hidden = false;

  const riskScore = Number.isFinite(data?.riskScore) ? data.riskScore : null;
  const derivedSeverity = severityFromScore(riskScore);

  score.textContent = riskScore == null ? "—" : `${riskScore}/100`;
  severity.textContent = derivedSeverity;
  severity.dataset.severity = derivedSeverity.toLowerCase();

  indicators.replaceChildren();
  const items = Array.isArray(data?.indicators) && data.indicators.length
    ? data.indicators
    : ["No indicators returned."];

  for (const item of items) {
    const li = document.createElement("li");
    li.textContent = item;
    indicators.appendChild(li);
  }

  const recommendation = data?.recommendation || "Review this URL carefully before continuing.";
  document.querySelector("#recommendation").textContent = recommendation;
}

async function scanCurrentTab(force = false) {
  state.hidden = false;
  resultBox.hidden = true;
  state.textContent = force ? "Re-scanning current page…" : "Scanning current page…";
  rescanButton.disabled = true;

  try {
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });

    if (!tab?.url || !/^https?:\/\//i.test(tab.url)) {
      state.textContent = "This browser page cannot be scanned.";
      return;
    }

    const data = await chrome.runtime.sendMessage({
      type: "SCAN_URL",
      url: tab.url,
      force
    });

    if (!data) throw new Error("No scan result returned.");
    renderResult(data);
  } catch (error) {
    state.hidden = false;
    resultBox.hidden = true;
    state.textContent = error?.message || "Unable to scan this page.";
  } finally {
    rescanButton.disabled = false;
  }
}

rescanButton.addEventListener("click", () => scanCurrentTab(true));
scanCurrentTab(false);
