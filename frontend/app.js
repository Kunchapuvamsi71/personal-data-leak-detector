const input = document.querySelector('#textInput');
const fileInput = document.querySelector('#fileInput');
const scanButton = document.querySelector('#scanButton');
const clearButton = document.querySelector('#clearButton');
const results = document.querySelector('#results');

fileInput.addEventListener('change', async () => {
  const file = fileInput.files[0];
  if (!file) return;
  if (file.size > 2 * 1024 * 1024) return showError('File is larger than 2 MB.');
  input.value = await file.text();
});

scanButton.addEventListener('click', async () => {
  const text = input.value.trim();
  if (!text) return showError('Enter text or choose a file first.');
  scanButton.disabled = true;
  scanButton.textContent = 'Scanning…';
  try {
    const response = await fetch('/api/scan', { method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify({text}) });
    const data = await response.json();
    if (!response.ok) throw new Error(data.detail || 'Scan failed');
    render(data);
  } catch (error) { showError(error.message); }
  finally { scanButton.disabled = false; scanButton.textContent = 'Scan text'; }
});

clearButton.addEventListener('click', () => { input.value = ''; fileInput.value = ''; results.classList.add('hidden'); results.innerHTML = ''; });

function showError(message) { results.className = 'card results error'; results.textContent = message; }
function render(data) {
  results.className = 'card results';
  const heading = data.total === 0 ? '<h2>No obvious leaks found</h2>' : `<h2>Scan complete <span class="risk ${data.risk}">${data.risk.toUpperCase()}</span></h2>`;
  const summary = `<div class="summary"><strong>${data.summary.total}</strong> finding${data.summary.total === 1 ? '' : 's'} · ${data.summary.critical} critical · ${data.summary.high} high · ${data.summary.medium} medium · ${data.summary.low} low</div>`;
  const rows = data.findings.map(item => `<article class="finding"><div><strong>${escapeHtml(item.type.replaceAll('_', ' '))}</strong><span class="badge ${item.severity}">${item.severity}</span></div><code>${escapeHtml(item.redacted_value)}</code><p>${escapeHtml(item.recommendation)}</p><small>Confidence: ${Math.round(item.confidence * 100)}%</small></article>`).join('');
  results.innerHTML = heading + summary + (rows || '<p>Pattern-based scans can miss unusual formats. Review the content manually before publishing.</p>');
}
function escapeHtml(value) { return value.replace(/[&<>'"]/g, character => ({'&':'&amp;','<':'&lt;','>':'&gt;',"'":'&#39;','"':'&quot;'}[character])); }
