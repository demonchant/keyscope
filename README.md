# KeyScope

**Live app:** [keyscope.onrender.com](https://keyscope.onrender.com) · [Open the dashboard](https://keyscope.onrender.com/dashboard)

KeyScope is a read-only monitor for NEAR delegated access keys. It reads finalized key permissions and receiver contract code, compares them with a baseline an operator explicitly approves, and reports changes. It does not connect to a wallet, sign transactions, move funds, or prevent another signer from acting. The product is deterministic and uses no AI service or model.

## Why KeyScope is useful

NEAR accounts can have multiple access keys with different permissions. A key may be limited to a specific contract, or it may have full account access. KeyScope gives an operator a repeatable way to inspect those permissions and spot changes against a baseline they deliberately approved.

The useful distinction is the comparison over time: KeyScope reads the current finalized key state, reads receiver contract code at that same block, then shows changes on a later scan with the block reference. This turns a one-time key inventory into a simple drift-monitoring workflow. It is valuable because it is read-only and does not ask users to connect a wallet or hand over signing authority.

KeyScope is a good fit for the NEAR HACKATHON AI Security & Defense track because it works directly with NEAR access-key permissions, including Function-Call keys used to delegate limited actions. It adds visibility into delegated-key and receiver-code changes. It is intentionally not an AI product, and it does not provide the track prompt's agent-side allow/warn/block enforcement or prevent a signer from acting. Treat it as a monitoring layer, not a security guarantee.

## What it checks

- Full-access, Function-Call, and gas-key permissions from NEAR JSON-RPC.
- Receiver contract code at the same finalized block as the access-key snapshot.
- New, removed, or changed keys and changed receiver-code digests against a browser-local approved baseline.
- Broad permissions, including unrestricted methods or missing Function-Call allowance.

Mainnet is selected explicitly in the UI; testnet is also available. The app only calls the fixed official NEAR RPC endpoint for the selected network. Reading public chain state does not require a funded wallet. Use an account you own or have permission to inspect. No live mainnet result has been verified in this development environment.

## Run locally

Requires Python 3.10+ and outbound HTTPS to NEAR RPC.

```powershell
python app.py
```

Open `http://127.0.0.1:8000` for the landing page, then choose **Open the dashboard** (or visit `/dashboard`). Select Mainnet, enter an account ID, and choose **Read finalized state**. Review the result before choosing **Approve this as baseline**. A second scan compares the current finalized state with that baseline. History and the baseline remain in this browser's local storage. Optional 60-second polling runs only while the dashboard is open.

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
```

The policy suite uses fixed fixtures only for pure comparison logic. It is not live chain evidence. Real browser acceptance uses the pinned Playwright setup in `e2e` and requires a real public account in `E2E_ACCOUNT`; an optional `E2E_CONTRACT` pins a real contract code read. Never use mocked RPC responses to claim a live scan.

## Limits

KeyScope is an observation tool, not an enforcement gateway or security guarantee. Baselines and history are editable local browser data. The monitor cannot revoke keys or stop a signer, and polling stops when the page closes. A drift demo requires an exact account-owner-authorized chain change and real before/after reads; a no-drift repeat is a valid demo.

## NEAR references

- [Access Keys](https://docs.near.org/protocol/accounts-contracts/access-keys)
- [NEAR JSON-RPC](https://docs.near.org/api/rpc/)
- [NEAR HACKATHON Track 6 prompt](https://github.com/nearai/near-hackathon-prompt-examples/blob/main/tracks/06-security.md)

Runtime dependencies: Python standard library and native browser JavaScript. Playwright 1.64.1 is for development-only browser tests. Licensed under MIT; see `LICENSE`.
