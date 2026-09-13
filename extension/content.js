(() => {
  const id = "innovex-security-warning";
  let sentSignals = false;

  function removeWarning() {
    document.getElementById(id)?.remove();
  }

  function collectPageSignals() {
    const text = (document.body?.innerText || document.documentElement?.innerText || "").slice(0, 50000).toLowerCase();
    const forms = Array.from(document.forms || []);
    const passwordFields = document.querySelectorAll('input[type="password"]').length;
    const emailFields = document.querySelectorAll('input[type="email"]').length;
    const sensitiveFields = document.querySelectorAll('input[name*="card" i], input[name*="cvv" i], input[name*="otp" i], input[name*="pin" i], input[name*="password" i]').length;
    const authWords = ["login", "log in", "sign in", "signin", "sign up", "register", "verify", "account", "password"];
    const matchedAuthWords = authWords.filter((word) => text.includes(word));

    const externalFormTargets = forms
      .map((form) => form.getAttribute("action") || "")
      .filter(Boolean)
      .filter((action) => {
        try {
          const target = new URL(action, location.href);
          return target.origin !== location.origin;
        } catch {
          return false;
        }
      }).length;

    return {
      passwordFields,
      emailFields,
      sensitiveFields,
      formCount: forms.length,
      externalFormTargets,
      matchedAuthWords: matchedAuthWords.slice(0, 6),
      hasPaymentLanguage: /(payment|credit card|debit card|billing|cvv|upi)/i.test(text),
      hasUrgencyLanguage: /(urgent|immediately|act now|suspended|expires today|verify now)/i.test(text)
    };
  }

  function sendSignals() {
    if (sentSignals) return;
    sentSignals = true;
    chrome.runtime.sendMessage({
      type: "PAGE_SIGNALS",
      url: location.href,
      signals: collectPageSignals()
    }).catch(() => {});
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

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", sendSignals, { once: true });
    setTimeout(sendSignals, 2500);
  } else {
    sendSignals();
  }
})();
