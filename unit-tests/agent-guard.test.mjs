import assert from 'node:assert/strict';
import {evaluateAgentCall, runGuardedCall} from '../agent-guard.mjs';

const contractId = 'token.near';
const recipientId = 'friend.near';
const publicKey = 'ed25519:test-only-public-key';
const key = {publicKey, kind:'functionCall', receiverId:contractId, methodNames:['ft_transfer'], allowance:'1000'};
const baseline = {network:'mainnet', account:'agent.near', keys:[key], codeSha256:{[contractId]:'code-a'}};
const scan = {network:'mainnet', account:'agent.near', finality:'final', blockHash:'hash-a', keys:[key], codeSha256:{[contractId]:'code-a'}, codeBytes:{[contractId]:12}};
const action = {contractId, recipientId, methodName:'ft_transfer', publicKey, depositYocto:'0', args:{receiver_id:recipientId, amount:'10'}};
const feed = {schemaVersion:1, entries:[]};
const activity = {available:true, recipientAgeDays:90, recipientTransactionCount:50, priorAgentInteraction:true};
const context = () => ({scan:{...scan, observedAt:new Date().toISOString()}, baseline, action, threatFeed:feed, accountSignals:activity, observedAt:new Date().toISOString()});

let signerCalls = 0;
let result = await runGuardedCall({action, refreshContext:async () => ({...context(), threatFeed:{schemaVersion:1,entries:[{network:'mainnet',accountId:recipientId,status:'verified',evidenceUrl:'https://example.invalid/fixture'}]}}), signer:async()=>{signerCalls++;}});
assert.equal(result.decision, 'block');
assert.equal(result.signerInvoked, false);
assert.equal(signerCalls, 0);

result = await runGuardedCall({action, refreshContext:async () => ({...context(), accountSignals:{...activity, priorAgentInteraction:false}}), confirmWarning:async()=>false, signer:async()=>{signerCalls++;}});
assert.equal(result.decision, 'warn');
assert.equal(result.signerInvoked, false);

result = await runGuardedCall({action, refreshContext:async()=>context(), signer:async()=>{signerCalls++; return 'fixture result';}});
assert.equal(result.decision, 'allow');
assert.equal(result.signerInvoked, true);
assert.equal(signerCalls, 1);

const assess = overrides => evaluateAgentCall({...context(), ...overrides});
assert.equal(assess({action:{...action, methodName:'transfer'}}).decision, 'block');
assert.equal(assess({action:{...action, depositYocto:'1'}}).decision, 'block');
assert.equal(assess({baseline:null}).decision, 'block');
assert.equal(assess({threatFeed:{schemaVersion:9, entries:[]}}).decision, 'block');
const staleAt = new Date(Date.now()-60_000).toISOString();
assert.equal(assess({scan:{...scan, observedAt:staleAt}, observedAt:staleAt}).decision, 'block');
assert.equal(assess({scan:{...scan, codeSha256:{[contractId]:'changed'}}}).decision, 'block');

console.log('agent guard: block prevents signer, warning requires explicit approval, allow invokes scoped signer once; required scope and evidence failures block');
