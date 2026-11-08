import { inspect } from './policy.mjs';

const ACCOUNT_ID = /^(?:[a-z0-9]+[-_])*[a-z0-9]+(?:\.(?:[a-z0-9]+[-_])*[a-z0-9]+)*$|^(?:[0-9a-f]{64}|0x[0-9a-f]{40}|0s[0-9a-f]{40})$/;

const finding = (code, message) => ({code, message});

function validThreatFeed(feed, allowFixture = false) {
  if (!feed || feed.schemaVersion !== 1 || !Array.isArray(feed.entries)) return false;
  return feed.entries.every(entry =>
    entry && ['mainnet', 'testnet'].includes(entry.network) &&
    typeof entry.accountId === 'string' && ACCOUNT_ID.test(entry.accountId) &&
    (entry.contractId === undefined || (typeof entry.contractId === 'string' && ACCOUNT_ID.test(entry.contractId))) &&
    ['verified', 'pending'].includes(entry.status) &&
    typeof entry.evidenceUrl === 'string' &&
    (entry.evidenceUrl.startsWith('https://') || (allowFixture && entry.evidenceUrl.startsWith('fixture://')))
  );
}

/** Deterministic decision for one agent call. Missing or inconsistent evidence fails closed. */
export function evaluateAgentCall(context, {allowFixtureFeed = false} = {}) {
  const block = [];
  const warn = [];
  const {scan, baseline, action, threatFeed, accountSignals, observedAt} = context || {};
  if (!scan || !Array.isArray(scan.keys) || !scan.codeSha256 || !scan.codeBytes) {
    return {decision:'block', reasons:[finding('scan_missing', 'A complete live KeyScope scan is required before signing.')]};
  }
  if (scan.finality !== 'final' || typeof scan.blockHash !== 'string' || !scan.blockHash) {
    block.push(finding('scan_not_final', 'The scan is not pinned to a finalized block.'));
  }
  const ageMs = Date.now() - Date.parse(observedAt || '');
  if (!Number.isFinite(ageMs) || ageMs < 0 || ageMs > 30_000) {
    block.push(finding('scan_stale', 'The preflight scan must be no more than 30 seconds old.'));
  }
  if (!baseline || baseline.network !== scan.network || baseline.account !== scan.account) {
    block.push(finding('baseline_missing', 'An explicitly approved baseline for this network and agent account is required.'));
  } else {
    for (const issue of inspect(scan, baseline)) {
      if (issue.level === 'block') block.push(finding('posture_drift', issue.title + ': ' + issue.text));
      else if (issue.level === 'warn') warn.push(finding('posture_warning', issue.title + ': ' + issue.text));
    }
  }
  if (!action || !ACCOUNT_ID.test(action.contractId || '') || !ACCOUNT_ID.test(action.recipientId || '') ||
      typeof action.methodName !== 'string' || !action.methodName || typeof action.publicKey !== 'string' || !action.publicKey) {
    block.push(finding('action_invalid', 'A contract, recipient, method, and selected access-key public key are required.'));
  } else {
    const key = scan.keys.find(item => item.publicKey === action.publicKey);
    if (!key) block.push(finding('key_not_found', 'The selected key is not present in the fresh account scan.'));
    else if (!['functionCall', 'gasFunctionCall'].includes(key.kind)) {
      block.push(finding('key_not_scoped', 'Agent actions must use a Function-Call key, never a Full-Access key.'));
    } else {
      if (key.receiverId !== action.contractId) block.push(finding('receiver_not_allowed', 'The Function-Call key is scoped to a different contract.'));
      if (Array.isArray(key.methodNames) && key.methodNames.length > 0 && !key.methodNames.includes(action.methodName)) {
        block.push(finding('method_not_allowed', 'The Function-Call key does not allow this method.'));
      }
      if (['ft_transfer', 'ft_transfer_call'].includes(action.methodName) && action.args?.receiver_id !== action.recipientId) {
        block.push(finding('recipient_mismatch', 'The recipient checked by KeyScope does not match the token-transfer call arguments.'));
      }
      if (!Array.isArray(key.methodNames) || key.methodNames.length === 0) warn.push(finding('all_methods_allowed', 'This Function-Call key allows every method on its receiver contract.'));
      if (key.allowance === null || key.allowance === undefined) warn.push(finding('unbounded_gas', 'This Function-Call key has no gas allowance ceiling.'));
    }
    if (action.depositYocto !== '0') block.push(finding('deposit_forbidden', 'Function-Call keys cannot attach NEAR; this guarded call requires zero attached deposit.'));
    const codeBytes = scan.codeBytes[action.contractId];
    const codeDigest = scan.codeSha256[action.contractId];
    if (!Number.isSafeInteger(codeBytes) || codeBytes < 0 ||
        typeof codeDigest !== 'string' || !/^[a-f0-9]{64}$/i.test(codeDigest)) {
      block.push(finding('contract_unchecked', 'A valid target contract code size and digest are required in the finalized scan.'));
    } else if (codeBytes === 0) {
      block.push(finding('not_a_contract', 'The target has no contract code at the scanned block.'));
    }
  }
  if (!validThreatFeed(threatFeed, allowFixtureFeed)) {
    block.push(finding('threat_feed_invalid', 'The shared threat feed is missing or malformed; signing is disabled.'));
  } else if (action) {
    const matches = threatFeed.entries.filter(entry => entry.network === scan.network &&
      [entry.accountId, entry.contractId].filter(Boolean).some(id => id === action.recipientId || id === action.contractId));
    if (matches.some(entry => entry.status === 'verified')) block.push(finding('threat_feed_match', 'The recipient or contract matches a verified shared threat report.'));
    else if (matches.some(entry => entry.status === 'pending')) warn.push(finding('threat_report_pending', 'There is an unverified shared report for this recipient or contract.'));
  }
  if (!accountSignals || accountSignals.available !== true) {
    block.push(finding('history_unavailable', 'Required account activity and prior-interaction signals could not be loaded.'));
  } else {
    if (!Number.isFinite(accountSignals.recipientAgeDays)) warn.push(finding('recipient_age_unknown', 'The recipient age could not be established from indexed history.'));
    else if (accountSignals.recipientAgeDays < 7) warn.push(finding('recipient_new', 'The recipient has less than seven days of observed indexed history.'));
    if (!Number.isFinite(accountSignals.recipientTransactionCount)) warn.push(finding('recipient_activity_unknown', 'Recipient activity history is incomplete.'));
    if (accountSignals.priorAgentInteraction !== true) warn.push(finding('no_prior_interaction', 'No successful prior interaction between this agent and recipient was found.'));
  }
  const decision = block.length ? 'block' : warn.length ? 'warn' : 'allow';
  return {decision, reasons:[...block, ...warn], scanBlockHash:scan.blockHash, network:scan.network, agentAccount:scan.account};
}

/** Mandatory wrapper entry point: refresh, evaluate, ask a human on WARN, then invoke the caller's scoped signer. */
export async function runGuardedCall({refreshContext, action, signer, confirmWarning}) {
  if (typeof refreshContext !== 'function' || typeof signer !== 'function') {
    throw new TypeError('refreshContext and the external Function-Call signer callback are required.');
  }
  let context;
  try { context = await refreshContext(action); }
  catch (error) {
    return {decision:'block', signerInvoked:false, reasons:[finding('preflight_failed', 'Fresh preflight failed: ' + String(error?.message || error))]};
  }
  const assessment = evaluateAgentCall({...context, action});
  if (assessment.decision === 'block') return {...assessment, signerInvoked:false};
  if (assessment.decision === 'warn') {
    if (typeof confirmWarning !== 'function' || await confirmWarning(assessment) !== true) {
      return {...assessment, signerInvoked:false, humanApproval:'not granted'};
    }
  }
  const guardedRequest = Object.freeze({
    publicKey:action.publicKey,
    receiverId:action.contractId,
    methodName:action.methodName,
    recipientId:action.recipientId,
    depositYocto:'0',
    args:action.args && typeof action.args === 'object' ? Object.freeze({...action.args}) : Object.freeze({})
  });
  const result = await signer(guardedRequest, {decision:assessment.decision, reasons:assessment.reasons});
  return {...assessment, signerInvoked:true, result};
}
