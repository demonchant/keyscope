import { inspect } from './policy.mjs';

const $ = id => document.getElementById(id);
const state = $('rpc-state');
const stateText = $('rpc-state-text');
const form = $('scan-form');
const report = $('report');
const baselineButton = $('save-baseline');
const exportButton = $('export-baseline');
let latest = null;
let watchTimer = null;
let busy = false;

function esc(value) {
  return String(value).replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
}
function validAccount(value) {
  return typeof value === 'string' && value.length >= 2 && value.length <= 64 && /^(?:[a-z0-9]+[-_])*[a-z0-9]+(?:\.(?:[a-z0-9]+[-_])*[a-z0-9]+)*$|^(?:[0-9a-f]{64}|0x[0-9a-f]{40}|0s[0-9a-f]{40})$/.test(value);
}
function setState(message, mode = '') {
  state.className = 'state ' + mode;
  stateText.textContent = message;
}
function storageKey(network, account) { return 'keyscope:v1:' + network + ':' + account; }
function currentInputs() {
  const network = $('network').value;
  const account = $('account').value.trim();
  if (!validAccount(account)) throw new Error('Enter a valid NEAR account ID.');
  const typedContracts = $('contracts').value.split(',').map(x => x.trim()).filter(Boolean);
  const saved = getRecord(network, account);
  const baselineContracts = Object.keys(saved.baseline?.codeSha256 || {});
  const contracts = [...new Set([...typedContracts, ...baselineContracts])];
  if (contracts.length > 20 || contracts.some(x => !validAccount(x))) throw new Error('Check the additional contract IDs (maximum 20).');
  return {network, account, contracts};
}
function render(scan, baseline, issues, history) {
  const top = issues.some(x => x.level === 'block') ? 'BLOCK' : issues.some(x => x.level === 'warn') ? 'REVIEW' : baseline ? 'MATCH' : 'UNBASELINED';
  const cls = top === 'BLOCK' ? 'block' : top === 'REVIEW' ? 'warn' : 'pass';
  const li = issues.length ? issues.map(x => '<article class="issue ' + x.level + '"><b>' + esc(x.title) + '</b><span>' + esc(x.text) + '</span></article>').join('') : '<p class="empty">No permission or code drift detected against the approved baseline.</p>';
  const keys = scan.keys.length ? scan.keys.map(k => {
    const gasKey = k.kind === 'gasFunctionCall' || k.kind === 'gasFullAccess';
    const budget = k.allowance === null ? 'unlimited' : (k.allowance || '—');
    const gasDetails = k.kind === 'gasFunctionCall' ? 'allowance ' + esc(budget) + ' · balance ' + esc(k.gasBalance || '—') + ' · lanes ' + esc(k.numNonces ?? '—') : k.kind === 'gasFullAccess' ? 'balance ' + esc(k.gasBalance || '—') + ' · lanes ' + esc(k.numNonces ?? '—') : esc(k.kind === 'functionCall' ? budget : '—');
    return '<tr><td><code>' + esc(k.publicKey) + '</code></td><td>' + (k.kind === 'fullAccess' || k.kind === 'gasFullAccess' ? 'FULL ACCESS' : k.kind === 'functionCall' ? 'FUNCTION CALL' : k.kind === 'gasFunctionCall' ? 'GAS FUNCTION CALL' : esc(k.kind)) + '</td><td>' + esc(k.receiverId || '—') + '</td><td>' + esc(k.methodNames ? (k.methodNames.length ? k.methodNames.join(', ') : 'all methods') : '—') + '</td><td>' + gasDetails + '</td></tr>';
  }).join('') : '<tr><td colspan="5">The account has no access keys in this finalized RPC response.</td></tr>';
  const code = Object.entries(scan.codeSha256).map(([id, hash]) => '<div class="code-row"><code>' + esc(id) + '<small>' + (scan.codeBytes?.[id] === 0 ? 'No contract code deployed at this block' : esc(scan.codeBytes?.[id] ?? 'unknown') + ' code bytes') + '</small></code><code>sha256:' + esc(hash) + '</code></div>').join('') || '<p class="empty">No Function-Call receivers or manually pinned contracts were returned.</p>';
  report.hidden = false;
  report.innerHTML = '<div class="result-head ' + cls + '"><div><p class="eyebrow">' + esc(top) + ' / ' + (baseline ? 'BASELINE COMPARISON' : 'LIVE SNAPSHOT') + '</p><h2>' + (top === 'BLOCK' ? 'Policy drift detected' : top === 'REVIEW' ? 'Review this account' : top === 'MATCH' ? 'No drift found' : 'Snapshot ready to review') + '</h2></div><div class="stamp">' + esc(new Date(scan.observedAt).toLocaleString()) + '<small>' + esc(scan.network) + ' · finalized' + (scan.blockHeight ? ' · block ' + esc(scan.blockHeight) : '') + '</small></div></div>' +
    '<div class="issues"><h3>Findings <span>' + issues.length + '</span></h3>' + li + '</div>' +
    '<div class="keys"><h3>Access keys <span>' + scan.keys.length + '</span></h3><div class="table-wrap" role="region" aria-label="Access key permissions table" tabindex="0"><table><caption class="sr-only">Access keys and their NEAR permissions</caption><thead><tr><th scope="col">PUBLIC KEY</th><th scope="col">PERMISSION</th><th scope="col">RECEIVER</th><th scope="col">METHODS</th><th scope="col">GAS BUDGET / KEY BALANCE</th></tr></thead><tbody>' + keys + '</tbody></table></div></div>' +
    '<div class="code-list"><h3>Observed receiver code</h3>' + code + '</div>' +
    '<div class="provenance"><b>Source</b> <a href="' + esc(scan.source) + '" target="_blank" rel="noreferrer">' + esc(scan.source) + '</a> · read-only JSON-RPC · account ' + esc(scan.account) + '<br><b>Finalized block hash</b> <code>' + esc(scan.blockHash || 'not supplied') + '</code><br><b>History</b> ' + history + ' recent observations stored in this browser. Timestamp is local observation time; key list and code reads are pinned to the same finalized block.</div>';
  baselineButton.textContent = baseline ? 'Replace approved baseline' : 'Approve this as baseline';
  updateActionButtons();
}
function getRecord(network, account) {
  try {
    const value = JSON.parse(localStorage.getItem(storageKey(network, account)) || '{}');
    if (!value || typeof value !== 'object' || Array.isArray(value)) return {};
    return {
      ...value,
      history: Array.isArray(value.history) ? value.history : []
    };
  } catch {
    return {};
  }
}
function updateActionButtons() {
  const baseline = latest ? getRecord(latest.network, latest.account).baseline : null;
  baselineButton.disabled = !latest?.keys || busy;
  exportButton.disabled = !baseline || busy;
  baselineButton.textContent = baseline ? 'Replace approved baseline' : 'Approve this as baseline';
  $('toggle-watch').disabled = !baseline || busy;
}
function stopWatch() {
  if (watchTimer) clearInterval(watchTimer);
  watchTimer = null;
  $('toggle-watch').textContent = 'Start 60-second checks';
}
function invalidateSnapshot() {
  const hadSnapshot = latest !== null;
  latest = null;
  updateActionButtons();
  stopWatch();
  report.hidden = true;
  if (hadSnapshot) setState('Selection changed. Read again before using the result.');
}
for (const id of ['network', 'account', 'contracts']) $(id).addEventListener('input', invalidateSnapshot);
for (const id of ['network']) $(id).addEventListener('change', invalidateSnapshot);
async function scan(showErrors = true) {
  if (busy) return;
  let input;
  try { input = currentInputs(); }
  catch (error) { if (showErrors) { setState('Input error. ' + error.message, 'fail'); report.hidden = false; report.innerHTML = '<div class="error" role="alert">' + esc(error.message) + '</div>'; } return; }
  busy = true;
  form.setAttribute('aria-busy', 'true');
  $('scan').disabled = true;
  setState('Reading finalized chain state. Please wait.');
  try {
    const response = await fetch('/api/scan', {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify(input)});
    const data = await response.json();
    if (!response.ok) throw new Error(data.error || 'NEAR RPC read failed (HTTP ' + response.status + ').');
    const latestInputs = currentInputs();
    if (JSON.stringify(latestInputs) !== JSON.stringify(input)) throw new Error('Inputs changed during the scan. Read the selected account again.');
    const scanData = {...data, observedAt:new Date().toISOString()};
    latest = scanData;
    let record = {};
    let storageError = '';
    try { record = JSON.parse(localStorage.getItem(storageKey(input.network, input.account)) || '{}'); }
    catch { storageError = 'Browser storage is unavailable or contains invalid saved data.'; }
    const issues = inspect(scanData, record.baseline);
    const history = [...(record.history || []), {observedAt:scanData.observedAt, blockHeight:scanData.blockHeight, issueCount:issues.filter(i => i.level !== 'info').length, status:issues.some(i=>i.level==='block')?'BLOCK':issues.some(i=>i.level==='warn')?'REVIEW':record.baseline?'MATCH':'UNBASELINED'}].slice(-20);
    record.history = history;
    try { localStorage.setItem(storageKey(input.network, input.account), JSON.stringify(record)); }
    catch { storageError = 'Browser storage could not save this observation; the live scan succeeded, but history was not saved.'; }
    render(scanData, record.baseline, issues, history.length);
    if (storageError) report.insertAdjacentHTML('beforeend', '<div class="error" role="alert">' + esc(storageError) + '</div>');
    const blocks = issues.filter(i=>i.level==='block').length;
    setState('Finalized state read. ' + (blocks ? blocks + ' blocking drifts found.' : 'Review the scan report below.'), blocks ? 'fail' : 'ok');
  } catch (error) {
    latest = null;
    updateActionButtons();
    setState('Chain read failed. ' + error.message, 'fail');
    report.hidden=false;
    report.innerHTML='<div class="error" role="alert"><b>No successful check.</b><br>' + esc(error.message) + '<p>Previous observations are not represented as current.</p></div>';
  } finally {
    busy = false;
    form.setAttribute('aria-busy', 'false');
    $('scan').disabled = false;
    updateActionButtons();
  }
}
form.addEventListener('submit', event => { event.preventDefault(); scan(); });
baselineButton.addEventListener('click', () => {
  if (!latest || busy) return;
  try {
    const record = getRecord(latest.network, latest.account);
    if (record.baseline && !window.confirm('Replace the previously approved baseline for this network and account?')) return;
    record.baseline = {network:latest.network, account:latest.account, approvedAt:new Date().toISOString(), keys:latest.keys, codeSha256:latest.codeSha256, blockHeight:latest.blockHeight, blockHash:latest.blockHash, source:latest.source};
    localStorage.setItem(storageKey(latest.network, latest.account), JSON.stringify(record));
    render(latest, record.baseline, inspect(latest, record.baseline), (record.history||[]).length);
    setState('Baseline approved in this browser.', 'ok');
  } catch {
    setState('Baseline not saved. Browser storage failed.', 'fail');
    report.insertAdjacentHTML('beforeend', '<div class="error" role="alert">Browser storage could not save the approved baseline.</div>');
  }
});
exportButton.addEventListener('click', () => {
  if (!latest || busy) return;
  const baseline = getRecord(latest.network, latest.account).baseline;
  if (!baseline) return;
  const blob = new Blob([JSON.stringify(baseline, null, 2)], {type:'application/json'});
  const url = URL.createObjectURL(blob);
  const link = document.createElement('a');
  link.href = url;
  link.download = 'keyscope-baseline-' + latest.network + '-' + latest.account.replace(/[^a-z0-9.-]/g, '_') + '.json';
  link.click();
  URL.revokeObjectURL(url);
  setState('Approved baseline exported. Keep the file out of source control.', 'ok');
});
 $('toggle-watch').addEventListener('click', event => {
  if (event.currentTarget.disabled) return;
    if (watchTimer) { stopWatch(); setState('Automatic checks paused.'); }
    else { watchTimer=setInterval(()=>scan(false), 60_000); event.target.textContent='Pause checks'; setState('Automatic checks started. They repeat every 60 seconds while this page stays open.', 'ok'); }
});
window.addEventListener('beforeunload', stopWatch);
