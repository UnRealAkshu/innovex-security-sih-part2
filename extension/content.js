(() => {
  const id = "innovex-security-warning";

  function removeWarning() {
    document.getElementById(id)?.remove();
  }

  function showWarning(result) {
    removeWarning();

    const severity = String(result?.severity || "").toLowerCase();
    if (!result || !["high", "critical"].includes(severity)) return;

    const banner = document.createElement("div");
    banner.id = id;

    const card = document.createElement("div");
    card.className = "innovex-warning-card";

    const title = document.createElement("div");
    title.className = "innovex-warning-title";
    title.textContent = "⚠️ Innovex Security Warning";

    const text = document.createElement("div");
    text.className = "innovex-warning-text";
    text.textContent = `This page may be dangerous. Risk level: ${result.severity}${result.riskScore != null ? ` (${result.riskScore}/100)` : ""}.`;

    const recommendation = document.createElement("div");
    recommendation.className = "innovex-warning-recommendation";
    recommendation.textContent = result.recommendation || "Avoid entering passwords, OTPs, or payment details.";

    const button = document.createElement("button");
    button.type = "button";
    button.id = "innovex-dismiss-warning";
    button.textContent = "Continue carefully";
    button.addEventListener("click", removeWarning);

    card.append(title, text, recommendation, button);
    banner.appendChild(card);
    document.documentElement.appendChild(banner);
  }

  chrome.runtime.onMessage.addListener((message) => {
    if (message?.type === "SCAN_RESULT") showWarning(message.result);
  });
})();
