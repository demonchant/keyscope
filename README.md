# KeyScope

**Live app:** [keyscope.onrender.com](https://keyscope.onrender.com) · [Open the dashboard](https://keyscope.onrender.com/dashboard)

KeyScope is a NEAR delegated-key monitor with a deterministic pre-sign counterparty guard for agent integrations. The public web app reads finalized permissions and receiver contract code, compares them with an operator-approved baseline, and reports drift. The agent wrapper can block a participating agent's call before it invokes that agent's supplied signer, or require human approval for a warning. KeyScope itself does not connect to a wallet, store signing keys, or submit transactions. The product uses no AI service or model.

## Problem

An agent can be given a NEAR access key so it can call a contract. The operator then needs to know whether that key still has the intended scope, whether the contract code changed, and whether the proposed counterparty has risk signals before the agent acts. A key inventory alone does not compare today's permissions and code with a previously approved state, and a warning shown after signing is too late.

## Solution

KeyScope reads the agent account's finalized access-key state and contract code, then compares those facts with an explicitly approved baseline. Before an integrated agent call, `agent-preflight.mjs` refreshes the scan, loads recipient activity and recent agent interactions from FastNear's Mainnet transaction-history API, and loads the shared reviewed threat feed. `agent-guard.mjs` makes a deterministic `allow`, `warn`, or `block` decision. A required call wrapper refuses to invoke the supplied signer on `block`, asks a human on `warn`, and permits only the matching Function-Call key, receiver contract, and allowed method. Full-Access keys are rejected for agent actions.

The guard only controls an agent that routes every signing call through the wrapper. A separate wallet, process, or signer can bypass it; KeyScope cannot revoke keys or prevent unrelated signers from acting. The wrapper receives the signing callback from the integrating agent and never receives or stores its private key.

## Why KeyScope is useful

NEAR accounts can have multiple access keys with different permissions. A key may be limited to a specific contract, or it may have full account access. KeyScope gives an operator a repeatable way to inspect those permissions and spot changes against a baseline they deliberately approved.

The useful distinction is the comparison over time: KeyScope reads the current finalized key state, reads receiver contract code at that same block, then shows changes on a later scan with the block reference. This turns a one-time key inventory into a simple drift-monitoring workflow. It is valuable because it is read-only and does not ask users to connect a wallet or hand over signing authority.

KeyScope targets the NEAR HACKATHON AI Security & Defense track's function-call-key, policy-engine, counterparty-check, and agent-wrapper requirements. The attack demo exercises a malicious injected instruction against a synthetic test feed; it makes no real payment and uses no AI model, as required by the project's no-AI constraint. The shared feed is populated only after a public report with evidence is reviewed; it currently contains no verified entries. [Track 6 prompt](https://github.com/nearai/near-hackathon-prompt-examples/blob/main/tracks/06-security.md).

The event page says the initial screen checks that a project runs and matches its README; human judges decide, using prior events' technical implementation, design, impact, originality, and sustainability as a guide. It does not publish those dimensions as a current weighted rubric. KeyScope's intended impact is reducing the chance that a participating agent calls a changed or reported counterparty under an unexpectedly broad key. User demand and market uniqueness are not yet validated. [Official event page](https://nearhackathon.com/).

## What it checks

- Full-access, Function-Call, and gas-key permissions from NEAR JSON-RPC.
- Receiver contract code at the same finalized block as the access-key snapshot.
- New, removed, or changed keys and changed receiver-code digests against a browser-local approved baseline.
- Broad permissions, including unrestricted methods or missing Function-Call allowance.
- Agent-call preflight: target contract and method must match the selected scoped key; reviewed blocklist matches block; new or incomplete history produces a warning; missing required data blocks the call.

Mainnet is selected explicitly in the UI; testnet is also available for monitoring. Reading public chain state does not require a funded wallet. Use an account you own or have permission to inspect. The monitor uses fixed NEAR RPC endpoints; the Mainnet agent preflight also requires FastNear transaction history. The user-recorded demo shows a successful Mainnet read; this workspace has not independently repeated that chain request.

## Run locally

Requires Python 3.10+ and outbound HTTPS to NEAR RPC.

```powershell
python app.py
```

Open `http://127.0.0.1:8000` for the landing page, then choose **Open the dashboard** (or visit `/dashboard`). Select Mainnet, enter an account ID, and choose **Read finalized state**. Review the result before choosing **Approve this as baseline**. A second scan compares the current finalized state with that baseline. History and baseline remain in this browser's local storage. **Export approved baseline** downloads the reviewed JSON for a local agent integration; keep that file private and out of Git. Optional 60-second polling runs only while the dashboard is open.

## Run with Docker Compose

Run:

```powershell
docker compose up --build
```

Open `http://127.0.0.1:8000` for the public landing page. Choose **Open the dashboard** to use the monitor at `/dashboard`. There is no login or password: anyone with the hosted URL can use the read-only app. Public deployments should use HTTPS; `render.yaml` prepares a Render Blueprint. Scans are rate-limited per client and across the server to protect the public RPC service.

## Verify

```powershell
python -m py_compile app.py unit-tests\test_account_ids.py
python -m unittest discover -s unit-tests -p 'test_*.py'
node unit-tests\policy.test.mjs
node unit-tests\agent-guard.test.mjs
node examples\agent-attack-demo.mjs
```

The policy and agent-guard suites use isolated fixed fixtures only for deterministic logic; they are not live chain evidence. `node examples/agent-attack-demo.mjs` prints the simulated injection attempt and confirms that the wrapper does not invoke its signer callback. The demo fixture is not a real account or threat report. Real browser acceptance uses the pinned Playwright setup in `e2e` and requires a real public account in `E2E_ACCOUNT`. Never use mocked RPC responses to claim a live scan.

## Agent integration and data sources

The agent preflight is Mainnet-only and requires all signals before a call. Configure the integrator with the public KeyScope URL, agent account, an operator-approved baseline exported from the dashboard, the proposed contract/recipient/method, and the agent's externally managed Function-Call signer callback. Call `guardedAgentCall` for every agent action; do not call the signer directly. The wrapper fails closed if the scan, approved baseline, FastNear history, or shared feed is unavailable. The browser dashboard remains read-only and does not connect the agent wallet.

| Track prompt requirement | KeyScope implementation |
| --- | --- |
| Return allow, warn, or block before an agent action | `evaluateAgentCall` derives a deterministic decision from the fresh scan, approved baseline, history signals, and shared feed. |
| Refuse to sign on block and ask a human on warn | `runGuardedCall` does not invoke the supplied signer on block; warnings require `confirmWarning(...) === true`. |
| Use one-contract Function-Call keys, never Full-Access keys | The guard requires the selected public key to be a Function-Call key scoped to the exact contract and method. It requires zero attached NEAR and checks FT recipient arguments against the recipient assessed. |
| Demonstrate an injection attempt against a reported address | `examples/agent-attack-demo.mjs` uses a deterministic simulated agent and a synthetic threat-feed fixture. It never connects to a wallet or sends a transaction. |
| Use an evidence-backed shared report feed | Every guard decision loads `threat-feed.json`. Reports enter through the GitHub issue form and require maintainer review before the feed changes. The current feed has no verified entries. |
| Describe data sources and failure handling | Sources and limits are listed below; missing required data blocks the guarded call. |

For a live agent, its wallet library must provide the external signer callback and use exactly the guarded request fields and public key it receives. KeyScope never imports the wallet credentials. The wrapper cannot stop an application that bypasses it or uses a separate signer.

- Finalized permissions, receiver code, and code digest: fixed NEAR Mainnet JSON-RPC through KeyScope's server.
- Activity age/count and recent interactions: [FastNear Transactions API](https://tx.main.fastnear.com/), using the documented account-history and transaction-lookup endpoints. “Age” means earliest observed indexed activity, not a proven account-creation date. Interaction checks inspect at most the 20 most recent transaction hashes returned for the agent, so a missing match means “not found in this sample,” not “never interacted.” FastNear is an external provider; an unavailable or malformed response blocks the guarded call. The service is credited here as required by its API documentation.
- Shared reports: `threat-feed.json`, served by KeyScope and checked on every guarded call. Anyone can submit a report with evidence through the repository's **Report a NEAR counterparty** issue form. A maintainer must verify evidence and update the reviewed feed; a report is never auto-blocked solely because it was submitted.
- Contract-code change: current code hash compared with the operator-approved baseline at the same finalized block as the key scan.

Function-Call keys can call only one receiver contract, optionally only listed methods, cannot attach NEAR, and can stop working when their allowance is exhausted. KeyScope rejects Full-Access keys for agent actions and warns on all-method or unbounded-allowance Function-Call keys. It does not inspect contract semantics or establish that a receiver is honest.

## Accessibility

KeyScope is a remote web app, so a user does not need to walk to an office or operate a physical kiosk. It can be opened from a phone, tablet, or computer with an internet connection.

- **Blind and low-vision users:** semantic page landmarks, a skip link, visible keyboard focus, labeled controls, screen-reader status announcements, table captions and headers, and text-based scan findings are implemented. Results are not conveyed by color alone. A screen reader can read the key permission, baseline status, error message, and block provenance.
- **Deaf and hard-of-hearing users:** the scan and errors are shown as text on screen. The product does not rely on an alert sound, spoken instruction, or audio response.
- **Non-speaking users:** no speech command or spoken response is required. The workflow uses standard browser fields, buttons, and text.
- **Users with limited mobility:** controls are keyboard-operable, have visible focus, and use a responsive layout for touch. These patterns are intended to work with switch devices and operating-system voice control.

These are accessibility features in the implementation, not a claim of certified WCAG conformance. Manual testing with screen readers, magnification, switch devices, and voice control remains outstanding.

## Limits

The dashboard is an observation tool, not an account-wide enforcement gateway or security guarantee. The agent wrapper gates only calls routed through it; it cannot revoke keys or stop a separate signer. Baselines and history are editable local browser data, and polling stops when the dashboard closes. A drift demo requires an exact account-owner-authorized chain change and real before/after reads; a no-drift repeat is a valid demo.

### What the current demo shows

The 1:58 screen recording, captured November 4, 2026, shows a user action followed by a finalized Mainnet scan, its RPC source and block reference, one Full-Access key, and a report labeled baseline comparison. The account had no Function-Call key, so no receiver contract was available for an automatic code read. The optional manual contract field was empty as well, so no receiver-code digest appears. This is why the clip does not show contract-code drift. It also does not show an AI agent using the account, a real threat-feed match, or a live agent signer being blocked. A Full-Access key on the inspected account is evidence of that permission on that account; it is not evidence that the key was misused or delegated to an agent.

The narration identifies NEAR Mainnet as the source of the on-chain permission data and names the NEAR HACKATHON AI Security & Defense track. The 1:58 video is prepared for the demo post; a public post has not yet been published. The hackathon guide requires the demo post to include video or screenshots and a complete action/result; it does not state a maximum video duration. The post must say the project was built at NEAR HACKATHON, tag `@NEARProtocol`, and include `#NEARHackathon`.

To demonstrate contract-code monitoring, enter an authorized deployed Mainnet contract in **Additional contracts to pin**, read and approve its actual code digest, then run a later live read. To demonstrate code drift, only compare after the contract owner authorizes a specific code change. To demonstrate agent enforcement, integrate a Function-Call signer adapter and route every agent signing request through `guardedAgentCall`; show the returned decision and confirm a blocked request never calls the signer. The isolated guard test is not a substitute for this live integration test.

## NEAR references

- [Access Keys](https://docs.near.org/protocol/accounts-contracts/access-keys)
- [NEAR JSON-RPC](https://docs.near.org/api/rpc/)
- [NEAR HACKATHON Track 6 prompt](https://github.com/nearai/near-hackathon-prompt-examples/blob/main/tracks/06-security.md)

Runtime dependencies: Python standard library and native browser JavaScript. Playwright 1.64.1 is for development-only browser tests. Licensed under MIT; see `LICENSE`.
