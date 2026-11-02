"""End-to-end framework: edge gateway write path, threshold key-release service (KRS),
and the retrieval client with blockchain-backed access control, integrity verification
and conformance checking (Algorithm 1 and Section V)."""
import base64
import hashlib
import json
import os
import threading
import time

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

import crypto_modes as cm
import edge
import threshold as th
from chain import Chain, Contract, keccak_sig, load_artifacts

ROLE = {"Doctor": 1, "Nurse": 2, "Admin": 3, "Analyst": 4, "Operator": 5}
ROLE_READ = {
    "Doctor": ["icu_monitor", "wearable_daily"],
    "Nurse": ["icu_monitor"],
    "Admin": list(edge.PROFILES),
    "Analyst": ["smart_meter", "wearable_daily", "env_sensor", "traffic_counter"],
    "Operator": ["industrial_plc", "cctv_frame", "traffic_counter", "env_sensor"],
}
# Non-conformance reason codes
NC_HEADER, NC_AEAD, NC_KEY = 1, 2, 3


def b32(s: str) -> bytes:
    return hashlib.sha256(s.encode()).digest()


def sha256(*parts: bytes) -> bytes:
    h = hashlib.sha256()
    for p in parts:
        h.update(p)
    return h.digest()


def key_commit(data_id: bytes, dek: bytes) -> str:
    return sha256(b"kc|", data_id, dek).hex()


def canon(obj) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode()


class Timer:
    def __init__(self):
        self.t = {}

    def run(self, name, fn, *a, **k):
        t0 = time.perf_counter()
        r = fn(*a, **k)
        self.t[name] = self.t.get(name, 0.0) + (time.perf_counter() - t0) * 1000
        return r


# --------------------------------------------------------------------------
class Deployment:
    """Deploys AdaptiveTrust and configures policy, devices, users and KRS nodes."""

    def __init__(self, chain_url, n_krs=3, t_krs=2, chain=None):
        self.chain = chain or Chain(chain_url)
        self.art = load_artifacts()
        acc = self.chain.accounts
        assert len(acc) >= 19, "need >= 19 unlocked accounts"
        self.owner = acc[0]
        self.edge_accounts = acc[1:9]
        self.krs_accounts = [acc[9], acc[17], acc[18]][:n_krs]
        self.user_accounts = acc[10:17]
        self.n_krs, self.t_krs = n_krs, t_krs
        addr, rc = self.chain.deploy(self.owner, self.art["AdaptiveTrust"]["bin"])
        self.deploy_gas = int(rc["gasUsed"], 16)
        self.c = Contract(self.chain, addr, self.art["AdaptiveTrust"]["hashes"])
        self.topics = {name: keccak_sig(sig) for name, sig in {
            "PolicyValidated": "PolicyValidated(bytes32,uint8,uint8)",
            "PolicyRejected": "PolicyRejected(bytes32,uint8,uint8,uint8)",
            "DecisionLogged": "DecisionLogged(bytes32,bytes32,bytes32,bytes32)",
            "AccessGranted": "AccessGranted(bytes32,address,uint256)",
            "AccessDenied": "AccessDenied(bytes32,address,uint8)",
            "TamperDetected": "TamperDetected(bytes32,address,bytes32)",
            "RecordFlagged": "RecordFlagged(bytes32,uint8)",
        }.items()}
        self.admin_gas = {}

    def _tx(self, fn, *a):
        rc = self.c.tx(self.owner, fn, *a)
        assert int(rc["status"], 16) == 1, (fn, rc)
        self.admin_gas.setdefault(fn, int(rc["gasUsed"], 16))
        return rc

    def configure(self, devices_per_type=10):
        """Policy/device setup, submitted back-to-back and then awaited."""
        calls = [("setEdgeNode", e, True) for e in self.edge_accounts]
        calls += [("setKrsNode", k, True) for k in self.krs_accounts]
        calls += [("setKrsThreshold", self.t_krs)]
        calls += [("setMinClass", b32(d), c) for d, c in edge.MIN_CLASS.items()]
        calls += [("setAllowedModes", c, m) for c, m in edge.ALLOWED.items()]
        calls += [("setRoleCanRead", ROLE[r], b32(t), True) for r, ts in ROLE_READ.items() for t in ts]
        calls += [("registerDevice", b32(f"{d}-{i:02d}"), b32(d)) for d in edge.PROFILES for i in range(devices_per_type)]
        pending = [(c[0], self.chain.submit(self.owner, self.c.address, self.c.data(*c), gas=300_000)) for c in calls]
        for fn, h in pending:
            rc = self.chain.wait(h)
            assert int(rc["status"], 16) == 1, (fn, rc)
            self.admin_gas.setdefault(fn, int(rc["gasUsed"], 16))

    def register_user(self, idx, role):
        addr = self.user_accounts[idx]
        if role:
            self._tx("registerUser", addr, ROLE[role])
        return addr

    def record(self, data_id):
        w = self.c.view("getRecord", data_id)
        return {"H": w[0], "ref": w[1], "dev": w[2], "C": int.from_bytes(w[5], "big"),
                "E": int.from_bytes(w[6], "big"), "exists": w[7][-1] == 1, "status": int.from_bytes(w[8], "big")}


# --------------------------------------------------------------------------
class KRSNode:
    """One key-release node. Holds only its Shamir share of each data key (sealed under its own
    master key) and its share of the Paillier decryption exponent. It verifies every on-chain
    grant independently and honours each grant once."""

    def __init__(self, idx, account, dep: Deployment, phe_share_fn, storage):
        self.idx, self.acct, self.dep = idx, account, dep
        self.master = AESGCM.generate_key(256)
        self.vault = {}
        self.used = set()
        self.online = True
        self.phe_partial = phe_share_fn
        self.storage = storage   # read access to off-chain storage, for evidence checks

    def deposit(self, data_id, share):
        x, y = share
        n = os.urandom(12)
        self.vault[data_id] = (x, n + AESGCM(self.master).encrypt(n, y.to_bytes(66, "big"), data_id))

    def _share(self, data_id):
        x, blob = self.vault[data_id]
        return x, int.from_bytes(AESGCM(self.master).decrypt(blob[:12], blob[12:], data_id), "big")

    def _check_grant(self, data_id, user, tx_hash):
        rc = self.dep.chain.rpc("eth_getTransactionReceipt", [tx_hash])
        if rc is None or int(rc["status"], 16) != 1 or rc["from"].lower() != user.lower():
            return None
        if (rc.get("to") or "").lower() != self.dep.c.address.lower():
            return None
        for lg in rc["logs"]:
            if lg["topics"][0] == self.dep.topics["AccessGranted"] and lg["topics"][1] == "0x" + data_id.hex() \
                    and lg["topics"][2][-40:].lower() == user[2:].lower():
                return int(lg["data"], 16)
        return None

    def release(self, data_id, user, user_pub, tx_hash, phe_values=None):
        if not self.online:
            return None
        req = self._check_grant(data_id, user, tx_hash)
        if req is None or req in self.used:
            return None
        self.used.add(req)
        out = {"idx": self.idx}
        if data_id in self.vault:
            x, y = self._share(data_id)
            out["share"] = (x, cm.wrap_key(user_pub, y.to_bytes(66, "big"), data_id + bytes([x])))
        if phe_values:
            out["phe"] = {k: self.phe_partial(self.idx, int(v, 16)) for k, v in phe_values.items()}
        return out

    def verify_evidence(self, data_id, dek, reason):
        """Check a reader's non-conformance evidence: the anchored envelope's committed key
        equals the presented key, yet the envelope does not open under the declared mode.
        Votes on-chain if the evidence holds."""
        rec = self.dep.record(data_id)
        ref, blob = self.storage(data_id)
        if sha256(ref.encode()) != rec["ref"] or sha256(blob, ref.encode()) != rec["H"]:
            return False                      # not the anchored object: not evidence
        env = json.loads(blob)
        h = env["h"]
        if h.get("kc") != key_commit(data_id, dek):
            return False                      # presented key is not the gateway's committed key
        ok = h["mode"] == rec["E"] and h["cls"] == rec["C"]
        if ok and rec["E"] != cm.NONE:
            try:
                _open_body(env, rec["E"], dek)
            except Exception:
                ok = False
        if ok:
            return False                      # conformant: evidence rejected
        rc = self.dep.c.tx(self.acct, "voteNonConformance", data_id, reason)
        return int(rc["status"], 16) == 1


def _open_body(env, mode, dek):
    aad = canon(env["h"])
    ct = base64.b64decode(env["ct"])
    nonce = bytes.fromhex(env["n"])
    if mode == cm.ASCON:
        return cm.ascon_decrypt(dek[:16], nonce, aad, ct)     # ASCON-AEAD128 uses the first 128 bits
    return cm.aes_decrypt(dek, nonce, aad, ct)


class KeyReleaseService:
    """t-of-n distributed KRS (n=1, t=1 gives the centralized baseline)."""

    def __init__(self, dep: Deployment, phe_pub, p, q, storage, n=None, t=None):
        self.dep = dep
        self.n = n or dep.n_krs
        self.t = t or dep.t_krs
        self.tp = th.ThresholdPaillier(phe_pub, p, q, self.n, self.t)
        self.nodes = [KRSNode(i + 1, dep.krs_accounts[i % len(dep.krs_accounts)], dep, self.tp.partial, storage)
                      for i in range(self.n)]

    def deposit(self, data_id, dek):
        for node, share in zip(self.nodes, th.shamir_split(dek, self.n, self.t)):
            node.deposit(data_id, share)

    def release(self, data_id, user, user_pub, tx_hash, phe_values=None):
        """Contacts nodes until t have answered (each verifies the grant itself)."""
        got = []
        for node in self.nodes:
            r = node.release(data_id, user, user_pub, tx_hash, phe_values)
            if r is not None:
                got.append(r)
            if len(got) == self.t:
                break
        return got if len(got) == self.t else None

    def audit_key(self, data_id, committed):
        """Joint audit for a disputed record (key-mismatch report): t nodes pool shares."""
        shares = [n._share(data_id) for n in self.nodes[:self.t] if data_id in n.vault]
        return key_commit(data_id, th.shamir_combine(shares)) == committed


# --------------------------------------------------------------------------
class UtilizationMonitor:
    """Gateway CPU headroom c = 1 - busy fraction over a sliding window."""

    def __init__(self, window=1.0):
        self.window, self.busy, self.lock = window, [], threading.Lock()

    def add(self, t0, t1):
        with self.lock:
            self.busy.append((t0, t1))

    def headroom(self):
        now = time.perf_counter()
        lo = now - self.window
        with self.lock:
            self.busy = [(a, b) for a, b in self.busy if b > lo]
            used = sum(min(b, now) - max(a, lo) for a, b in self.busy)
        return max(0.0, 1.0 - used / self.window)


class Gateway:
    def __init__(self, dep: Deployment, account, krs: KeyReleaseService, phe_pub, sql, ipfs,
                 ipfs_threshold=4096, all_ipfs=False, load_fn=None, power=1.0):
        self.dep, self.acct, self.krs = dep, account, krs
        self.phe_pub = phe_pub
        self.mask_key = os.urandom(32)
        self.sql, self.ipfs = sql, ipfs
        self.ipfs_threshold = ipfs_threshold
        self.all_ipfs = all_ipfs
        self.index = {}   # off-chain index dataId -> storage reference
        self.util = UtilizationMonitor()
        self.power = power
        self.load_fn = load_fn or self._default_load

    def _default_load(self):
        c = self.util.headroom()
        m = edge.gateway_load()[1]
        return c, m, self.power

    # ---- Edge analysis + decision (Algorithm 1)
    def analyse(self, r: edge.Record):
        S = edge.sensitivity(r.dtype, r.payload)
        c, m, b = self.load_fn()
        R = edge.resource_score(c, m, b, r.net)
        C, E = edge.decide(r.dtype, S, R, r.budget_ms, r.rt)
        return S, R, C, E

    # ---- Protection
    def protect(self, r: edge.Record, C: int, E: int, header_override=None, encrypt_as=None,
                store_plaintext=False):
        """header_override / encrypt_as / store_plaintext are used only by the
        non-conformance experiments to emulate a misbehaving gateway."""
        prof = edge.PROFILES[r.dtype]
        header = {"v": 2, "id": r.data_id.hex(), "dtype": r.dtype, "cls": C, "mode": E, "ts": r.ts}
        payload = dict(r.payload)
        masked, phe = {}, {}
        if E == cm.AES_MASK:
            for f in prof["ids"]:
                if f in payload:
                    masked[f] = cm.mask_token(self.mask_key, str(payload.pop(f)))
            header["dev"] = cm.mask_token(self.mask_key, r.dev_id)
        elif E == cm.NONE:
            header["dev"] = r.dev_id
        if E == cm.AES_PHE:
            for f in prof["phe"]:
                phe[f] = format(self.phe_pub.encrypt(cm.fp_encode(payload.pop(f))), "x")
        header["masked"] = masked
        body = canon(payload) + (b"\x00" + r.blob if r.blob else b"")
        mode = E if encrypt_as is None else encrypt_as
        dek, nonce = None, b""
        if E != cm.NONE:
            dek = os.urandom(32)
            header["kc"] = key_commit(r.data_id, dek)
        if header_override:
            header.update(header_override)
        aad = canon(header)
        if E == cm.NONE or store_plaintext:
            ct = body
        elif mode == cm.ASCON:
            nonce = os.urandom(16)
            ct = cm.ascon_encrypt(dek[:16], nonce, aad, body)
        else:
            nonce = os.urandom(12)
            ct = cm.aes_encrypt(dek, nonce, aad, body)
        env = {"h": header, "n": nonce.hex(), "phe": phe, "ct": base64.b64encode(ct).decode()}
        return canon(env), dek

    def store(self, blob: bytes) -> str:
        if self.all_ipfs or len(blob) > self.ipfs_threshold:
            return "ipfs:" + self.ipfs.add(blob)
        return self.sql.put(blob)

    def fetch(self, ref):
        if ref.startswith("ipfs:"):
            return self.ipfs.cat(ref[5:])
        return self.sql.get(ref)

    def storage_view(self, data_id):
        ref = self.index[data_id]
        return ref, self.fetch(ref)

    def anchor(self, r, C, E, h, ref):
        rc = self.dep.c.tx(self.acct, "logDecision", r.data_id, b32(r.dev_id), C, E, h, sha256(ref.encode()))
        accepted = any(lg["topics"][0] == self.dep.topics["DecisionLogged"] for lg in rc["logs"])
        return accepted, int(rc["gasUsed"], 16)

    def ingest(self, r: edge.Record, override=None, deposit_key=None, **misbehave):
        """Full write path. `override=(C, E)` and `misbehave` emulate a malicious gateway."""
        tm = Timer()
        t_start = time.perf_counter()
        S, R, C, E = tm.run("edge_analysis", self.analyse, r)
        if override:
            C, E = override
        env, dek = tm.run("encrypt", self.protect, r, C, E, **misbehave)
        ref = tm.run("store", self.store, env)
        h = tm.run("hash", sha256, env, ref.encode())
        if dek is not None:
            tm.run("key_deposit", self.krs.deposit, r.data_id, deposit_key or dek)
        self.util.add(t_start, time.perf_counter())
        accepted, gas = tm.run("chain_anchor", self.anchor, r, C, E, h, ref)
        if accepted:
            self.index[r.data_id] = ref
        return dict(S=S, R=R, C=C, E=E, accepted=accepted, gas=gas, size=len(env), ref=ref, t=tm.t)


# --------------------------------------------------------------------------
class Client:
    def __init__(self, dep: Deployment, account, gw: Gateway, krs: KeyReleaseService, hybrid=True):
        self.dep, self.acct, self.gw, self.krs = dep, account, gw, krs
        self.keys = cm.UserKeys() if hybrid else None
        if not hybrid:
            self.sk, pk = cm.x25519_keypair()
            self.pub = pk
        else:
            self.pub = self.keys.pub

    def _unwrap(self, blob, ctx):
        return cm.unwrap_key(self.keys if self.keys else self.sk, blob, ctx)

    def fetch(self, ref):
        return self.gw.fetch(ref)

    def retrieve(self, data_id: bytes, report=True):
        """Authorized retrieval. Returns (status, plaintext_or_None, timings, gas)."""
        tm = Timer()
        rc = tm.run("access_request", self.dep.c.tx, self.acct, "requestAccess", data_id)
        gas = int(rc["gasUsed"], 16)
        if not any(lg["topics"][0] == self.dep.topics["AccessGranted"] for lg in rc["logs"]):
            return "DENIED", None, tm.t, gas
        ref = self.gw.index[data_id]
        blob = tm.run("fetch", self.fetch, ref)
        rec = tm.run("chain_read", self.dep.record, data_id)

        def verify():
            return sha256(ref.encode()) == rec["ref"] and sha256(blob, ref.encode()) == rec["H"]
        if not tm.run("verify", verify):
            if report:
                rc2 = self.dep.c.tx(self.acct, "reportTamper", data_id, sha256(blob, ref.encode()))
                gas += int(rc2["gasUsed"], 16)
            return "TAMPER", None, tm.t, gas
        env = json.loads(blob)
        h = env["h"]

        def nonconformant(reason, dek=None):
            if report:
                self.dep.c.tx(self.acct, "reportNonConformance", data_id, reason)
                if dek is not None:
                    for node in self.krs.nodes:
                        node.verify_evidence(data_id, dek, reason)
                elif reason == NC_KEY and not self.krs.audit_key(data_id, h.get("kc")):
                    for node in self.krs.nodes[:self.krs.t]:
                        node.dep.c.tx(node.acct, "voteNonConformance", data_id, reason)
            return "NONCONFORMANT", None, tm.t, gas

        mode = rec["E"]
        dek = None
        if mode != cm.NONE:
            parts = tm.run("key_release", self.krs.release, data_id, self.acct, self.pub, rc["transactionHash"],
                           env["phe"] or None)
            if parts is None:
                return "KEY_REFUSED", None, tm.t, gas

            def combine():
                shares = [(p["share"][0], int.from_bytes(self._unwrap(p["share"][1], data_id + bytes([p["share"][0]])),
                                                          "big")) for p in parts]
                return th.shamir_combine(shares, 32)
            dek = tm.run("key_combine", combine)
            if h.get("kc") != key_commit(data_id, dek):
                return nonconformant(NC_KEY)
        if h.get("mode") != mode or h.get("cls") != rec["C"] or h.get("id") != data_id.hex():
            return nonconformant(NC_HEADER, dek)

        def open_env():
            body = base64.b64decode(env["ct"]) if mode == cm.NONE else _open_body(env, mode, dek)
            js, _, raw = body.partition(b"\x00")
            out = json.loads(js)
            out.update(h["masked"])
            if env["phe"]:
                for k in env["phe"]:
                    out[k] = cm.fp_decode(self.krs.tp.combine({p["idx"]: p["phe"][k] for p in parts}))
            return out, raw
        try:
            pt = tm.run("decrypt", open_env)
        except Exception:
            return nonconformant(NC_AEAD, dek)
        return "OK", pt, tm.t, gas
