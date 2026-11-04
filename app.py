"""Local, read-only KeyScope dashboard with fixed-origin NEAR RPC access."""
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
import base64
import hashlib
import ipaddress
import json
import os
import re
import threading
import time
import urllib.error
import urllib.request
from collections import deque

RPC = {
    "mainnet": "https://rpc.mainnet.near.org",
    "testnet": "https://rpc.testnet.near.org",
}
MAX_BODY = 16_384
# A 4 MiB NEAR contract expands to about 5.6 MB when base64-encoded in JSON.
MAX_RESPONSE = 6_000_000
MAX_SCANS_PER_MINUTE = 120
MAX_CLIENT_SCANS_PER_MINUTE = 6
SCAN_TIMES = deque()
CLIENT_SCAN_TIMES = {}
SCAN_LOCK = threading.Lock()
ACCOUNT = re.compile(r"^(?:[a-z0-9]+[-_])*[a-z0-9]+(?:\.(?:[a-z0-9]+[-_])*[a-z0-9]+)*$|^(?:[0-9a-f]{64}|0x[0-9a-f]{40}|0s[0-9a-f]{40})$")


def valid_account(value):
    return isinstance(value, str) and 2 <= len(value) <= 64 and ACCOUNT.fullmatch(value) is not None


class RpcFailure(Exception):
    pass


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, response, code, message, headers, new_url):
        raise urllib.error.HTTPError(request.full_url, code, "NEAR RPC redirect refused", headers, response)


RPC_OPENER = urllib.request.build_opener(NoRedirect)
class Handler(SimpleHTTPRequestHandler):
    def do_HEAD(self):
        self.send_error(405, "HEAD is not supported")

    def do_GET(self):
        if self.path == "/health":
            self.respond(200, {"status": "ready", "rpc": "not checked"})
        elif self.path in ("/dashboard", "/dashboard/"):
            self.path = "/dashboard.html"
            super().do_GET()
        elif self.path in ("/", "/index.html", "/dashboard.html", "/style.css", "/app.js", "/policy.mjs", "/keyscope-hero.webp", "/threat-feed.json"):
            super().do_GET()
        else:
            self.send_error(404)

    def do_POST(self):
        if self.path != "/api/scan":
            self.send_error(404)
            return
        if not self.scan_rate_allowed():
            self.respond(429, {"error": "Scan limit reached. Wait before trying again."})
            return
        try:
            size = int(self.headers.get("Content-Length", "0"))
            if size < 1 or size > MAX_BODY:
                self.respond(400, {"error": "Request size is invalid."})
                return
            body = json.loads(self.rfile.read(size))
            network = body.get("network") if isinstance(body, dict) else None
            account = body.get("account") if isinstance(body, dict) else None
            contracts = body.get("contracts", []) if isinstance(body, dict) else None
            if network not in RPC:
                self.respond(400, {"error": "Choose mainnet or testnet explicitly."})
                return
            if not valid_account(account):
                self.respond(400, {"error": "Enter a valid NEAR account ID."})
                return
            if not isinstance(contracts, list) or len(contracts) > 20 or any(
                not valid_account(c) for c in contracts
            ):
                self.respond(400, {"error": "Contract list is invalid (maximum 20 account IDs)."})
                return
            first_page = self.rpc_query(network, {"request_type": "view_access_key_list", "finality": "final", "account_id": account, "limit": 100})
            if not isinstance(first_page.get("keys"), list):
                raise RpcFailure("NEAR RPC returned an invalid access-key response.")
            block_hash = first_page.get("block_hash")
            if not isinstance(block_hash, str) or not block_hash:
                raise RpcFailure("NEAR RPC response did not include a finalized block hash.")
            keys = list(first_page["keys"])
            last_key = first_page.get("last_key")
            seen_cursors = set()
            while last_key is not None:
                if not isinstance(last_key, str) or not last_key or last_key in seen_cursors:
                    raise RpcFailure("NEAR RPC returned an invalid access-key pagination cursor.")
                if len(keys) >= 500:
                    raise RpcFailure("This account has more than 500 keys; scan is capped for safety.")
                seen_cursors.add(last_key)
                page = self.rpc_query(network, {"request_type": "view_access_key_list", "block_id": block_hash, "account_id": account, "after_key": last_key, "limit": min(100, 500 - len(keys))})
                if not isinstance(page.get("keys"), list) or page.get("block_hash") != block_hash:
                    raise RpcFailure("NEAR RPC returned a malformed or inconsistent access-key page.")
                keys.extend(page["keys"])
                last_key = page.get("last_key")
            if len(keys) > 500:
                raise RpcFailure("This account has more than 500 keys; scan is capped for safety.")
            clean_keys = []
            seen_public_keys = set()
            for item in keys:
                if not isinstance(item, dict) or not isinstance(item.get("public_key"), str) or not item["public_key"] or item["public_key"] in seen_public_keys or not isinstance(item.get("access_key"), dict):
                    raise RpcFailure("NEAR RPC returned a malformed access-key entry.")
                seen_public_keys.add(item["public_key"])
                key = item["access_key"]
                permission = key.get("permission")
                if permission == "FullAccess":
                    clean_keys.append({"publicKey": item["public_key"], "kind": "fullAccess"})
                elif isinstance(permission, dict) and (isinstance(permission.get("FunctionCall"), dict) or isinstance(permission.get("GasKeyFunctionCall"), dict)):
                    gas_key = isinstance(permission.get("GasKeyFunctionCall"), dict)
                    fc = permission["GasKeyFunctionCall"] if gas_key else permission["FunctionCall"]
                    if not valid_account(fc.get("receiver_id")) or not isinstance(fc.get("method_names"), list) or any(not isinstance(name, str) for name in fc["method_names"]):
                        raise RpcFailure("NEAR RPC returned malformed Function-Call permission fields.")
                    allowance = fc.get("allowance")
                    if allowance is not None and (not isinstance(allowance, str) or not allowance.isdigit()):
                        raise RpcFailure("NEAR RPC returned a malformed Function-Call allowance.")
                    balance = fc.get("balance") if gas_key else None
                    if gas_key and (not isinstance(balance, str) or not balance.isdigit()):
                        raise RpcFailure("NEAR RPC returned a malformed gas-key balance.")
                    lanes = fc.get("num_nonces") if gas_key else None
                    if gas_key and (not isinstance(lanes, int) or isinstance(lanes, bool) or lanes < 1):
                        raise RpcFailure("NEAR RPC returned a malformed gas-key nonce-lane count.")
                    clean_keys.append({"publicKey": item["public_key"], "kind": "gasFunctionCall" if gas_key else "functionCall", "receiverId": fc["receiver_id"], "methodNames": fc["method_names"], "allowance": allowance, "gasBalance": balance, "numNonces": lanes})
                elif isinstance(permission, dict) and isinstance(permission.get("GasKeyFullAccess"), dict):
                    gas = permission["GasKeyFullAccess"]
                    balance = gas.get("balance")
                    lanes = gas.get("num_nonces")
                    if not isinstance(balance, str) or not balance.isdigit() or not isinstance(lanes, int) or isinstance(lanes, bool) or lanes < 1:
                        raise RpcFailure("NEAR RPC returned a malformed gas-key balance or nonce-lane count.")
                    clean_keys.append({"publicKey": item["public_key"], "kind": "gasFullAccess", "gasBalance": balance, "numNonces": lanes})
                else:
                    clean_keys.append({"publicKey": item["public_key"], "kind": "other"})
            receivers = sorted(set(contracts) | {k["receiverId"] for k in clean_keys if k["kind"] in ("functionCall", "gasFunctionCall")})
            if len(receivers) > 20:
                raise RpcFailure("This account references more than 20 receiver contracts; scan is capped for safety.")
            code = {}
            code_bytes = {}
            for receiver in receivers:
                result = self.rpc_query(network, {"request_type": "view_code", "block_id": block_hash, "account_id": receiver})
                if result.get("block_hash") is not None and result.get("block_hash") != block_hash:
                    raise RpcFailure("NEAR RPC returned contract code from a different block than the key list.")
                encoded = result.get("code_base64") if isinstance(result, dict) else None
                if not isinstance(encoded, str):
                    raise RpcFailure("NEAR RPC returned malformed contract code for " + receiver + ".")
                try:
                    raw = base64.b64decode(encoded, validate=True)
                except Exception as exc:
                    raise RpcFailure("NEAR RPC returned invalid base64 contract code for " + receiver + ".") from exc
                code[receiver] = hashlib.sha256(raw).hexdigest()
                code_bytes[receiver] = len(raw)
            block = first_page.get("block_height")
            if not isinstance(block, int) or isinstance(block, bool) or block < 0:
                block = None
            self.respond(200, {"network": network, "account": account, "keys": clean_keys, "codeSha256": code, "codeBytes": code_bytes, "blockHeight": block, "blockHash": block_hash, "source": RPC[network], "finality": "final"})
        except (ValueError, json.JSONDecodeError) as exc:
            self.respond(400, {"error": str(exc)})
        except RpcFailure as exc:
            self.respond(502, {"error": str(exc)[:400]})
        except urllib.error.HTTPError as exc:
            try:
                parsed = json.loads(exc.read(65_536))
                message = parsed.get("error", {}).get("message", "NEAR RPC rejected the read request.")
            except Exception:
                message = "NEAR RPC rejected the read request (HTTP " + str(exc.code) + ")."
            self.respond(502, {"error": str(message)[:400]})
        except (urllib.error.URLError, TimeoutError, OSError, json.JSONDecodeError):
            self.respond(502, {"error": "Selected NEAR RPC could not be reached. No chain state was read; check network access and retry."})

    def rpc_query(self, network, params):
        payload = json.dumps({"jsonrpc": "2.0", "id": "keyscope", "method": "query", "params": params}).encode()
        request = urllib.request.Request(RPC[network], data=payload, headers={"Content-Type": "application/json"}, method="POST")
        with RPC_OPENER.open(request, timeout=20) as response:
            raw = response.read(MAX_RESPONSE + 1)
        if len(raw) > MAX_RESPONSE:
            raise RpcFailure("NEAR RPC response exceeded the size limit.")
        try:
            data = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise RpcFailure("NEAR RPC returned malformed JSON.") from exc
        if not isinstance(data, dict) or data.get("error"):
            error = data.get("error", {}) if isinstance(data, dict) else {}
            message = error.get("message") if isinstance(error, dict) else error
            raise RpcFailure(str(message or "NEAR RPC returned an invalid response.")[:400])
        result = data.get("result")
        if not isinstance(result, dict):
            raise RpcFailure("NEAR RPC response has no result object.")
        return result

    def respond(self, status, value):
        encoded = json.dumps(value).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(encoded)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(encoded)

    def scan_rate_allowed(self):
        now = time.monotonic()
        client = self.client_address[0]
        # Render documents X-Forwarded-For as its client-IP header. Only accept
        # a syntactically valid first address; otherwise use the socket peer.
        forwarded = self.headers.get("X-Forwarded-For", "").split(",", 1)[0].strip()
        if forwarded:
            try:
                client = str(ipaddress.ip_address(forwarded))
            except ValueError:
                pass
        with SCAN_LOCK:
            while SCAN_TIMES and now - SCAN_TIMES[0] >= 60:
                SCAN_TIMES.popleft()
            times = CLIENT_SCAN_TIMES.setdefault(client, deque())
            while times and now - times[0] >= 60:
                times.popleft()
            if len(SCAN_TIMES) >= MAX_SCANS_PER_MINUTE or len(times) >= MAX_CLIENT_SCANS_PER_MINUTE:
                return False
            SCAN_TIMES.append(now)
            times.append(now)
            if len(CLIENT_SCAN_TIMES) > 2048:
                for address in [address for address, recent in CLIENT_SCAN_TIMES.items() if not recent or now - recent[-1] >= 60]:
                    CLIENT_SCAN_TIMES.pop(address, None)
            return True

    def end_headers(self):
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Content-Security-Policy", "default-src 'self'; connect-src 'self'; img-src 'self' data:; style-src 'self'; script-src 'self'; base-uri 'none'; frame-ancestors 'none'")
        super().end_headers()

    def version_string(self):
        return "KeyScope"


if __name__ == "__main__":
    host = os.environ.get("KEYSCOPE_HOST", "127.0.0.1")
    if host not in ("127.0.0.1", "0.0.0.0"):
        raise SystemExit("KEYSCOPE_HOST must be 127.0.0.1 or 0.0.0.0")
    try:
        port = int(os.environ.get("PORT", "8000"))
    except ValueError as exc:
        raise SystemExit("PORT must be an integer from 1 to 65535") from exc
    if not 1 <= port <= 65535:
        raise SystemExit("PORT must be an integer from 1 to 65535")
    print("KeyScope available at http://%s:%s" % (host, port))
    ThreadingHTTPServer((host, port), Handler).serve_forever()
