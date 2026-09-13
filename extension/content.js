(() => {
  const id = "innovex-security-warning";

  function removeWarning() {
    document.getElementById(id)?.remove();
  }

  function showWarning(result) {
    removeWarning();
    if (!result || !["high", "critical"].includes(String(result.severity).toLowerCase())) return;

    const banner = document.createElement("div");
    banner.id = id;
    banner.innerHTML = `
      <div class="innovex-warning-card">
        <div class="innovex-warning-title">⚠️ Innovex Security Warning</div>
        <div class="innovex-warning-text">This page may be dangerous. Risk level: <strong>${result.severity}</strong>${result.riskScore != null ? ` (${result.riskScore}/100)` : ""}.</div>
        <div class="innovex-warning-recommendation">${result.recommendation || "Avoid entering passwords, OTPs, or payment details."}</div>
        <button id="innovex-dismiss-warning">Continue carefully</button>
      </div>`;
    document.documentElement.appendChild(banner);
    document.getElementById("innovex-dismiss-warning")?.addEventListener("click", removeWarning);
  }

  chrome.runtime.onMessage.addListener((message) => {
    if (message?.type === "SCAN_RESULT") showWarning(message.result);
  });
})();
