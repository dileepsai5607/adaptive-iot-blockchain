"""Minimal JSON-RPC client for a local EVM node (Anvil) with ABI encoding
for the static types used by AdaptiveTrust plus `string` for the baseline."""
import json
import threading
import os
import subprocess
import time
import urllib.request

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CAST = os.path.join(ROOT, "tools", "dl_foundry", "cast")
ANVIL = os.path.join(ROOT, "tools", "dl_foundry", "anvil")

_opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))


def keccak_sig(sig: str) -> str:
    """keccak256 of an event/function signature, via Foundry's cast."""
    return subprocess.check_output([CAST, "keccak", sig], text=True).strip()


# --------------------------- ABI encoding ---------------------------------
def _word(b: bytes) -> bytes:
    return b.rjust(32, b"\x00")


def enc_arg(typ: str, val):
    if typ == "bytes32":
        assert isinstance(val, (bytes, bytearray)) and len(val) == 32
        return bytes(val), None
    if typ.startswith("uint"):
        return int(val).to_bytes(32, "big"), None
    if typ == "bool":
        return (1 if val else 0).to_bytes(32, "big"), None
    if typ == "address":
        return _word(bytes.fromhex(val[2:])), None
    if typ == "string":
        raw = val.encode()
        padded = raw + b"\x00" * ((32 - len(raw) % 32) % 32)
        return None, len(raw).to_bytes(32, "big") + padded
    raise ValueError(typ)


def encode_call(selector: str, types, args) -> str:
    heads, tails = [], []
    for t, a in zip(types, args):
        h, tail = enc_arg(t, a)
        heads.append(h)
        tails.append(tail)
    head_len = 32 * len(types)
    out_head, out_tail = b"", b""
    for h, tail in zip(heads, tails):
        if h is not None:
            out_head += h
        else:
            out_head += (head_len + len(out_tail)).to_bytes(32, "big")
            out_tail += tail
    return "0x" + selector + (out_head + out_tail).hex()


def decode_words(data_hex: str):
    raw = bytes.fromhex(data_hex[2:])
    return [raw[i:i + 32] for i in range(0, len(raw), 32)]


# --------------------------- RPC client -----------------------------------
class Chain:
    MAX_FEE = hex(10 * 10**9)   # 10 gwei cap; dev chains run far below this
    PRIO_FEE = hex(1)

    def __init__(self, url="http://127.0.0.1:8545"):
        self.url = url
        self._id = 0
        self.accounts = self.rpc("eth_accounts")
        self.chain_id = self.rpc("eth_chainId")
        self._nonce = {}
        self._nlock = threading.Lock()
        self._alock = {}

    def rpc(self, method, params=None):
        self._id += 1
        body = json.dumps({"jsonrpc": "2.0", "id": self._id, "method": method, "params": params or []}).encode()
        req = urllib.request.Request(self.url, data=body, headers={"Content-Type": "application/json"})
        with _opener.open(req, timeout=60) as r:
            resp = json.loads(r.read())
        if "error" in resp:
            raise RuntimeError(resp["error"])
        return resp["result"]

    def _acct_lock(self, frm):
        with self._nlock:
            return self._alock.setdefault(frm.lower(), threading.Lock())

    def submit(self, frm, to, data, gas=3_000_000):
        """Submit a fully specified EIP-1559 transaction (client-side nonce management);
        returns the tx hash without waiting for inclusion."""
        key = frm.lower()
        with self._acct_lock(frm):
            if key not in self._nonce:
                self._nonce[key] = int(self.rpc("eth_getTransactionCount", [frm, "pending"]), 16)
            tx = {"from": frm, "input": data, "gas": hex(gas), "nonce": hex(self._nonce[key]),
                  "maxFeePerGas": self.MAX_FEE, "maxPriorityFeePerGas": self.PRIO_FEE,
                  "chainId": self.chain_id, "type": "0x2"}
            if to:
                tx["to"] = to
            try:
                h = self.rpc("eth_sendTransaction", [tx])
            except Exception:
                self._nonce.pop(key, None)   # resync on next submit
                raise
            self._nonce[key] += 1
            return h

    def send(self, frm, to, data, gas=3_000_000):
        return self.wait(self.submit(frm, to, data, gas))

    def wait(self, h, poll=0.002):
        while True:
            rc = self.rpc("eth_getTransactionReceipt", [h])
            if rc is not None:
                return rc
            time.sleep(poll)

    def call(self, to, data, frm=None):
        tx = {"to": to, "data": data}
        if frm:
            tx["from"] = frm
        return self.rpc("eth_call", [tx, "latest"])

    # Well-known public key of dev account 0 of the standard test mnemonic
    # ("test test ... junk"), used by Anvil, Hardhat and Reth --dev. Never use outside dev chains.
    DEV_KEY0 = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"

    def deploy(self, frm, bytecode):
        try:
            rc = self.send(frm, None, "0x" + bytecode, gas=8_000_000)
        except RuntimeError:
            # Some dev signers (e.g. Reth) reject create requests: sign the creation tx with cast.
            assert frm.lower() == self.accounts[0].lower()
            with self._acct_lock(frm):
                out = subprocess.check_output([CAST, "send", "--rpc-url", self.url, "--private-key", self.DEV_KEY0,
                                               "--gas-limit", "8000000", "--json", "--create", "0x" + bytecode],
                                              text=True)
                self._nonce.pop(frm.lower(), None)
            rc = self.wait(json.loads(out)["transactionHash"])
        assert int(rc["status"], 16) == 1, rc
        return rc["contractAddress"], rc


class Contract:
    def __init__(self, chain: Chain, address: str, hashes: dict):
        self.chain = chain
        self.address = address
        self.sel = {}
        for sig, s in hashes.items():
            name = sig.split("(")[0]
            types = [t for t in sig[sig.index("(") + 1:-1].split(",") if t]
            self.sel[name] = (s, types)

    def data(self, fn, *args):
        s, types = self.sel[fn]
        return encode_call(s, types, args)

    def tx(self, frm, fn, *args, gas=1_000_000):
        return self.chain.send(frm, self.address, self.data(fn, *args), gas=gas)

    def view(self, fn, *args, frm=None):
        return decode_words(self.chain.call(self.address, self.data(fn, *args), frm))


def load_artifacts():
    with open(os.path.join(ROOT, "build", "combined.json")) as f:
        d = json.load(f)["contracts"]
    return {k.split(":")[1]: v for k, v in d.items()}


RETH = os.path.join(ROOT, "tools", "dl_reth", "reth")


def start_reth(port=8555, block_time=None, datadir=None, log_path=None):
    """Reth (production Ethereum execution client) in --dev mode.
    block_time=None -> a block is sealed as soon as one transaction is pending (instant
    inclusion); block_time='2s' -> fixed block interval, like a PoA consortium chain."""
    import shutil
    datadir = datadir or os.path.join(ROOT, "run", f"reth-{port}")
    if os.path.exists(datadir):
        shutil.rmtree(datadir)
    p2p = port + 20000
    args = [RETH, "node", "--dev", "--datadir", datadir, "--http", "--http.addr", "127.0.0.1",
            "--http.port", str(port), "--http.api", "eth,net,web3,txpool", "--port", str(p2p),
            "--discovery.port", str(p2p), "--disable-discovery", "--authrpc.port", str(port + 1000),
            "--ipcdisable", "--log.stdout.filter", "error", "--txpool.max-account-slots", "10000",
            "--txpool.pending-max-count", "100000", "--txpool.basefee-max-count", "100000"]
    args += ["--dev.block-time", block_time] if block_time else ["--dev.block-max-transactions", "1"]
    p = subprocess.Popen(args, stdout=open(log_path or os.devnull, "w"), stderr=subprocess.STDOUT)
    url = f"http://127.0.0.1:{port}"
    for _ in range(400):
        try:
            Chain(url)
            return p, url
        except Exception:
            time.sleep(0.05)
    p.kill()
    raise RuntimeError("reth did not start")


def start_anvil(port=8545, block_time=None, log_path=None):
    args = [ANVIL, "--port", str(port), "--accounts", "40", "--silent",
            "--gas-limit", "30000000", "--code-size-limit", "50000",
            "--prune-history"]   # keep no historical states on disk (they reach tens of GB)
    if block_time:
        args += ["--block-time", str(block_time)]
    p = subprocess.Popen(args, stdout=open(log_path or os.devnull, "w"), stderr=subprocess.STDOUT)
    url = f"http://127.0.0.1:{port}"
    for _ in range(200):
        try:
            Chain(url)
            return p, url
        except Exception:
            time.sleep(0.05)
    p.kill()
    raise RuntimeError("anvil did not start")
