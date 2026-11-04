import assert from 'node:assert/strict';
import { inspect } from '../policy.mjs';

// These fixed fixtures exercise pure comparison logic only. They are never served by the app,
// used by Playwright, or evidence of a live NEAR read.
const scoped = { publicKey:'unit-test-key', kind:'functionCall', receiverId:'contract.near', methodNames:['read'], allowance:'100', gasBalance:null };
const baseline = { keys:[scoped], codeSha256:{'contract.near':'digest-a'} };
const scan = (keys=[scoped], codeSha256={'contract.near':'digest-a'}, codeBytes={'contract.near':10}) => ({keys, codeSha256, codeBytes});
const cases = [];
function test(name, fn) { cases.push([name, fn]); }

test('unchanged least-privilege key and code produce no findings', () => {
  assert.deepEqual(inspect(scan(), baseline), []);
});

test('method expansion blocks the changed key scope', () => {
  const changed = {...scoped, methodNames:['read','transfer']};
  assert.ok(inspect(scan([changed]), baseline).some(x => x.level === 'block' && x.title === 'Key permission changed'));
});

test('new full-access key is blocking drift', () => {
  const full = {publicKey:'new-unit-key', kind:'fullAccess'};
  assert.ok(inspect(scan([scoped, full]), baseline).some(x => x.level === 'block' && x.title === 'New full-access key'));
});

test('removed key is a warning and does not remove baseline code pin', () => {
  assert.ok(inspect(scan([], {'contract.near':'digest-a'}), baseline).some(x => x.level === 'warn' && x.title === 'Baseline key is absent'));
});

test('changed receiver code digest is blocking drift', () => {
  assert.ok(inspect(scan([scoped], {'contract.near':'digest-b'}), baseline).some(x => x.level === 'block' && x.title === 'Contract code changed'));
});

test('unbounded function-call and empty contract code are warnings', () => {
  const broad = {...scoped, methodNames:[], allowance:null};
  const issues = inspect(scan([broad], {'contract.near':'digest-a'}, {'contract.near':0}), baseline);
  assert.ok(issues.some(x => x.title === 'Function-Call key allows all receiver methods'));
  assert.ok(issues.some(x => x.title === 'No gas allowance ceiling'));
  assert.ok(issues.some(x => x.title === 'No contract code at receiver'));
});

test('gas full-access key is surfaced as unrestricted', () => {
  const gas = {publicKey:'gas-unit-key', kind:'gasFullAccess', gasBalance:'500', numNonces:8};
  const issues = inspect(scan([scoped, gas]), baseline);
  assert.ok(issues.some(x => x.level === 'block' && x.title === 'New full-access key'));
  assert.ok(issues.some(x => x.level === 'warn' && x.title === 'Full-access key present'));
});

test('gas-key nonce-lane changes are permission drift', () => {
  const gas = {publicKey:'gas-unit-key', kind:'gasFunctionCall', receiverId:'contract.near', methodNames:['read'], allowance:'100', gasBalance:'500', numNonces:8};
  const gasBaseline = {keys:[gas], codeSha256:{}};
  assert.ok(inspect(scan([{...gas, numNonces:4}], {}, {}), gasBaseline).some(x => x.level === 'block' && x.title === 'Key permission changed'));
});

test('gas-key balance changes are not permission drift', () => {
  const gas = {publicKey:'gas-unit-key', kind:'gasFunctionCall', receiverId:'contract.near', methodNames:['read'], allowance:'100', gasBalance:'500', numNonces:8};
  const gasBaseline = {keys:[gas], codeSha256:{}};
  const issues = inspect(scan([{...gas, gasBalance:'400'}], {}, {}), gasBaseline);
  assert.ok(!issues.some(x => x.title === 'Key permission changed'));
});

let failures = 0;
for (const [name, fn] of cases) {
  try { fn(); process.stdout.write('PASS ' + name + '\n'); }
  catch (error) { failures++; process.stderr.write('FAIL ' + name + ': ' + error.message + '\n'); }
}
process.stdout.write(cases.length + ' cases, ' + failures + ' failures\n');
if (failures) process.exitCode = 1;
