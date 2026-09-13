const state = document.querySelector('#state');
const resultBox = document.querySelector('#result');
const score = document.querySelector('#score');
const severity = document.querySelector('#severity');
const indicators = document.querySelector('#indicators');
const recommendation = document.querySelector('#recommendation');

async function scanCurrentTab() {
  state.hidden = false;
  resultBox.hidden = true;
  state.textContent = 'Scanning current page…';

  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  if (!tab?.url || !/^https?:\/\//i.test(tab.url)) {
    state.textContent = 'This browser page cannot be scanned.';
    return;
  }

  chrome.runtime.sendMessage({ type: 'SCAN_URL', url: tab.url }, (data) => {
    if (chrome.runtime.lastError || !data) {
      state.textContent = 'Unable to scan this page.';
      return;
    }

    state.hidden = true;
    resultBox.hidden = false;
    score.textContent = data.riskScore == null ? '—' : `${data.riskScore}/100`;
    severity.textContent = data.severity || 'unknown';
    severity.dataset.severity = data.severity || 'unknown';
    indicators.innerHTML = '';
    (data.indicators || ['No indicators returned']).forEach((item) => {
      const li = document.createElement('li');
      li.textContent = item;
      indicators.appendChild(li);
    });
    recommendation.textContent = data.recommendation || '';
  });
}

document.querySelector('#rescan').addEventListener('click', scanCurrentTab);
scanCurrentTab();
