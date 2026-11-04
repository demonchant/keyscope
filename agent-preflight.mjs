import {runGuardedCall} from './agent-guard.mjs';

const MAINNET_HISTORY = 'https://tx.main.fastnear.com';

async function jsonResponse(response, source) {
  if (!response.ok) throw new Error(source + ' returned HTTP ' + response.status);
  return response.json();
}

async function postJson(fetchImpl, url, value) {
  return fetchImpl(url, {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify(value)});
}

function timestampMs(value) {
  if (typeof value === 'number' || (typeof value === 'string' && /^\d+$/.test(value))) {
    const numeric = Number(value);
    return numeric > 100_000_000_000_000 ? numeric / 1_000_000 : numeric * 1000;
  }
  const parsed = Date.parse(value);
  return Number.isFinite(parsed) ? parsed : null;
}

async function accountHistory(fetchImpl, accountId, {signerOnly = false} = {}) {
  const common = {account_id:accountId, limit:50};
  if (signerOnly) common.is_real_signer = true;
  const [recentResponse, oldestResponse] = await Promise.all([
    postJson(fetchImpl, MAINNET_HISTORY + '/v0/account', {...common, desc:true}),
    postJson(fetchImpl, MAINNET_HISTORY + '/v0/account', {...common, limit:1, desc:false})
  ]);
  const recent = await jsonResponse(recentResponse, 'FastNear Transactions API');
  const oldest = await jsonResponse(oldestResponse, 'FastNear Transactions API');
  if (!Array.isArray(recent.account_txs) || !Array.isArray(oldest.account_txs)) {
    throw new Error('FastNear returned an invalid account history response.');
  }
  const earliestMs = timestampMs(oldest.account_txs[0]?.tx_block_timestamp);
  const count = Number.isFinite(recent.txs_count) ? recent.txs_count : null;
  return {recent:recent.account_txs, transactionCount:count, earliestMs};
}

async function recentReceivers(fetchImpl, history) {
  const hashes = [...new Set(history.map(row => row.transaction_hash).filter(value => typeof value === 'string'))].slice(0, 20);
  if (!hashes.length) return null;
  const response = await postJson(fetchImpl, MAINNET_HISTORY + '/v0/transactions', {tx_hashes:hashes});
  const data = await jsonResponse(response, 'FastNear Transactions API');
  if (!Array.isArray(data.transactions)) throw new Error('FastNear returned an invalid transaction detail response.');
  return data.transactions.flatMap(tx => [tx.receiver_id, tx.real_receiver_id, tx.transaction?.receiver_id].filter(value => typeof value === 'string'));
}

/** Fetches all required live signals. Any missing provider result rejects the preflight. */
export async function refreshCounterpartyContext({keyscopeUrl, network, agentAccount, baseline, action, fetchImpl = fetch}) {
  if (network !== 'mainnet') throw new Error('Agent preflight currently requires NEAR Mainnet; no testnet history source is configured.');
  if (!keyscopeUrl || !agentAccount || !baseline || !action) throw new Error('KeyScope URL, agent account, approved baseline, and call action are required.');
  const base = new URL(keyscopeUrl);
  if (base.protocol !== 'https:' && base.hostname !== 'localhost' && base.hostname !== '127.0.0.1') {
    throw new Error('KeyScope preflight requires HTTPS outside local development.');
  }
  const contracts = [...new Set([action.contractId, action.recipientId])];
  const scanPromise = postJson(fetchImpl, new URL('/api/scan', base), {network, account:agentAccount, contracts})
    .then(response => jsonResponse(response, 'KeyScope scan'))
    .then(scan => ({...scan, observedAt:new Date().toISOString()}));
  const [scan, feedResponse, agentHistory, recipientHistory] = await Promise.all([
    scanPromise,
    fetchImpl(new URL('/threat-feed.json', base)),
    accountHistory(fetchImpl, agentAccount, {signerOnly:true}),
    accountHistory(fetchImpl, action.recipientId)
  ]);
  const threatFeed = await jsonResponse(feedResponse, 'KeyScope shared threat feed');
  const receivers = await recentReceivers(fetchImpl, agentHistory.recent);
  const now = Date.now();
  const observedAt = scan.observedAt;
  const interactionKnown = Array.isArray(receivers);
  return {
    scan,
    baseline,
    threatFeed,
    observedAt,
    accountSignals:{
      available:true,
      recipientAgeDays:recipientHistory.earliestMs === null ? null : Math.max(0, (now-recipientHistory.earliestMs)/86_400_000),
      recipientTransactionCount:recipientHistory.transactionCount,
      priorAgentInteraction:interactionKnown ? receivers.includes(action.recipientId) : null,
      activitySource:MAINNET_HISTORY
    }
  };
}

/** Required entry point for agent actions: every call refreshes KeyScope and history before signer invocation. */
export function guardedAgentCall({keyscopeUrl, network = 'mainnet', agentAccount, baseline, action, signer, confirmWarning, fetchImpl = fetch}) {
  return runGuardedCall({
    action,
    signer,
    confirmWarning,
    refreshContext: currentAction => refreshCounterpartyContext({keyscopeUrl, network, agentAccount, baseline, action:currentAction, fetchImpl})
  });
}
