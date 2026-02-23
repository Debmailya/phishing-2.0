const form = document.getElementById('scan-form');
const scanBtn = document.getElementById('scan-btn');
const statusEl = document.getElementById('status');
const resultCard = document.getElementById('result-card');
const predictionEl = document.getElementById('prediction');
const threatPillEl = document.getElementById('threat-pill');
const phishingEl = document.getElementById('confidence-phishing');
const legitEl = document.getElementById('confidence-legitimate');
const domainEl = document.getElementById('domain');
const analyzedAtEl = document.getElementById('analyzed-at');
const reasonsEl = document.getElementById('reasons');

document.getElementById('year').textContent = new Date().getFullYear();

const threatStyles = {
  Low: { bg: 'rgba(88, 218, 131, 0.15)', color: '#7cf4a1', border: '#58da83' },
  Medium: { bg: 'rgba(255, 175, 57, 0.15)', color: '#ffbf68', border: '#ffaf39' },
  High: { bg: 'rgba(255, 98, 98, 0.15)', color: '#ff8383', border: '#ff6262' },
  Critical: { bg: 'rgba(255, 58, 58, 0.2)', color: '#ff7f7f', border: '#ff4141' }
};

const setStatus = (message, isError = false) => {
  statusEl.textContent = message;
  statusEl.style.color = isError ? '#ff8b8b' : '#9eb3d4';
};

const renderResult = (data) => {
  resultCard.hidden = false;
  predictionEl.textContent = `${data.prediction} (${data.threatLevel} Risk)`;
  predictionEl.style.color = data.prediction === 'Phishing' ? '#ff8383' : '#83f7b4';

  phishingEl.textContent = `Phishing: ${data.confidence.phishing}%`;
  legitEl.textContent = `Legitimate: ${data.confidence.legitimate}%`;
  domainEl.textContent = data.domain;
  analyzedAtEl.textContent = new Date(data.analyzedAt).toLocaleString();

  const style = threatStyles[data.threatLevel] || threatStyles.Low;
  threatPillEl.textContent = `${data.threatLevel} Threat`;
  threatPillEl.style.background = style.bg;
  threatPillEl.style.color = style.color;
  threatPillEl.style.borderColor = style.border;

  reasonsEl.innerHTML = '';
  data.reasons.forEach((reason) => {
    const li = document.createElement('li');
    li.textContent = reason;
    reasonsEl.appendChild(li);
  });
};

form.addEventListener('submit', async (event) => {
  event.preventDefault();
  const formData = new FormData(form);
  const url = String(formData.get('url') || '').trim();

  if (!url) {
    setStatus('Please enter a URL to analyze.', true);
    return;
  }

  scanBtn.disabled = true;
  setStatus('Running real-time scan...');

  try {
    const response = await fetch('/api/scan', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ url })
    });

    const payload = await response.json();
    if (!response.ok) {
      throw new Error(payload.error || 'Scan failed.');
    }

    renderResult(payload);
    setStatus(`Scan complete: ${payload.scannedUrl}`);
  } catch (error) {
    setStatus(error instanceof Error ? error.message : 'Unexpected error occurred.', true);
  } finally {
    scanBtn.disabled = false;
  }
});
