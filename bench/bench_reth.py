"""E2 (latency) and E4 (throughput) on Reth, a production Ethereum execution client,
running a dev chain with a fixed 1 s block interval (PoA-consortium-like).

Write path: off-chain stages are on the critical path; anchoring is submitted
asynchronously and its inclusion latency is measured separately (submit -> block seen).
Read path: the access-request transaction must be included before key release."""
import json
import os
import random
import statistics as st
import sys
import threading
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))
import crypto_modes as cm  # noqa: E402
import edge  # noqa: E402
from env_setup import bring_up, make_gateway  # noqa: E402
from framework import Client, b32, sha256  # noqa: E402

OUT = os.path.join(os.path.dirname(__file__), "..", "results")
BLOCK = os.environ.get("BLOCK_TIME", "1s")
N_WRITE = int(os.environ.get("N_WRITE", 1500))
RATE = float(os.environ.get("RATE", 50))          # offered load for the latency run, records/s
N_READ = int(os.environ.get("N_READ", 100))
SYNC_SECONDS = float(os.environ.get("SYNC_SECONDS", 20))
N_ASYNC = int(os.environ.get("N_ASYNC", 3000))


def summarize(xs):
    xs = sorted(xs)
    return {"n": len(xs), "mean": st.mean(xs), "median": st.median(xs), "p95": xs[max(0, int(0.95 * len(xs)) - 1)],
            "p99": xs[max(0, int(0.99 * len(xs)) - 1)], "std": st.pstdev(xs), "max": xs[-1]}


class InclusionTracker(threading.Thread):
    """Polls for new blocks and stamps the wall-clock time each tx hash is first seen in a block."""

    def __init__(self, chain):
        super().__init__(daemon=True)
        self.chain, self.seen, self.stop = chain, {}, False
        self.last = int(chain.rpc("eth_blockNumber"), 16)
        self.block_gas = []

    def run(self):
        while not self.stop:
            n = int(self.chain.rpc("eth_blockNumber"), 16)
            now = time.perf_counter()
            while self.last < n:
                try:
                    b = self.chain.rpc("eth_getBlockByNumber", [hex(self.last + 1), False])
                except Exception:
                    b = None
                if b is None:              # block not yet served by this node: retry next poll
                    break
                self.last += 1
                for h in b["transactions"]:
                    self.seen[h] = now
                self.block_gas.append((int(b["gasUsed"], 16), int(b["gasLimit"], 16), len(b["transactions"])))
            time.sleep(0.01)


def main():
    if os.environ.get("CHAIN") == "besu":
        import besu_net
        procs, chain = besu_net.start(n_validators=int(os.environ.get("VALIDATORS", 4)))
        dep, krs, pub, sql, ipfs = bring_up(chain=chain, port=int(os.environ.get("RETH_PORT", 8575)))
    else:
        dep, krs, pub, sql, ipfs = bring_up(client="reth", block_time=BLOCK, port=int(os.environ.get("RETH_PORT", 8575)))
    tr = InclusionTracker(dep.chain)
    tr.start()
    gw = make_gateway(dep, krs, pub, sql, ipfs)
    out = {"client": "besu 25.10.0 QBFT x%s" % os.environ.get("VALIDATORS", 4) if os.environ.get("CHAIN") == "besu"
           else "reth 1.9.3 --dev", "block_time": BLOCK}

    # ------------------------- E2 write path (paced) -------------------------
    recs = edge.generate(N_WRITE, seed=11)
    rows = []
    t_start = time.perf_counter()
    for i, r in enumerate(recs):
        target = t_start + i / RATE
        d = target - time.perf_counter()
        if d > 0:
            time.sleep(d)
        t0 = time.perf_counter()
        S, R, C, E = gw.analyse(r)
        t1 = time.perf_counter()
        env, dek = gw.protect(r, C, E)
        t2 = time.perf_counter()
        ref = gw.store(env)
        t3 = time.perf_counter()
        h = sha256(env, ref.encode())
        if dek is not None:
            krs.deposit(r.data_id, dek)          # Shamir split + seal at 3 KRS nodes
        t4 = time.perf_counter()
        t4h = t4
        txh = dep.chain.submit(gw.acct, dep.c.address,
                               dep.c.data("logDecision", r.data_id, b32(r.dev_id), C, E, h, sha256(ref.encode())),
                               gas=300_000)
        t5 = time.perf_counter()
        gw.index[r.data_id] = ref
        rows.append(dict(dtype=r.dtype, E=E, budget=r.budget_ms, tx=txh, t_submit=t5,
                         st={"edge_analysis": (t1 - t0) * 1e3, "encrypt": (t2 - t1) * 1e3, "store": (t3 - t2) * 1e3,
                             "hash_deposit": (t4 - t3) * 1e3, "submit": (t5 - t4h) * 1e3}))
    accepted = 0
    for row in rows:
        rc = dep.chain.wait(row["tx"])
        accepted += any(lg["topics"][0] == dep.topics["DecisionLogged"] for lg in rc["logs"])
        row["gas"] = int(rc["gasUsed"], 16)
    time.sleep(0.2)
    for row in rows:
        row["inclusion_ms"] = (tr.seen[row["tx"]] - row["t_submit"]) * 1e3
    out["write_accepted"] = accepted / len(rows)
    e2w = {}
    for m in sorted({x["E"] for x in rows}):
        ws = [x for x in rows if x["E"] == m]
        e2w[cm.MODE_NAMES[m]] = {
            **{s: summarize([w["st"][s] for w in ws]) for s in ws[0]["st"]},
            "critical_path": summarize([sum(w["st"].values()) for w in ws]),
            "anchor_inclusion": summarize([w["inclusion_ms"] for w in ws]),
            "count": len(ws)}
    out["e2_write"] = e2w
    out["budget_met_critical_path"] = sum(sum(w["st"].values()) <= w["budget"] for w in rows) / len(rows)
    out["anchor_inclusion_all"] = summarize([w["inclusion_ms"] for w in rows])
    print("write", {m: (round(v["critical_path"]["median"], 3), round(v["anchor_inclusion"]["median"], 1))
                    for m, v in e2w.items()}, "accepted", out["write_accepted"], flush=True)

    # ------------------------- E2 read path -------------------------
    admin = Client(dep, dep.register_user(0, "Admin"), gw, krs)
    rng = random.Random(3)
    reads = {}
    by_id = {r.data_id: row for r, row in zip(recs, rows)}
    for r in rng.sample(recs, N_READ):
        status, pt, t, gas = admin.retrieve(r.data_id)
        assert status == "OK", status
        reads.setdefault(cm.MODE_NAMES[by_id[r.data_id]["E"]], []).append(t)
    out["e2_read"] = {m: {**{s: summarize([t[s] for t in v]) for s in v[0]},
                          "total": summarize([sum(t.values()) for t in v])} for m, v in reads.items()}
    print("read", {m: round(v["total"]["median"], 1) for m, v in out["e2_read"].items()}, flush=True)

    # ------------------------- E4 throughput -------------------------
    base = [r for r in edge.generate(N_ASYNC * 2, seed=31) if r.dtype != "cctv_frame"]
    tp = []
    for mode in ("sync", "async"):
        for k in (1, 2, 4, 8):
            gws = [make_gateway(dep, krs, pub, sql, ipfs, idx=i) for i in range(k)]
            pool = base[:N_ASYNC] if mode == "async" else base
            chunks = [pool[i::k] for i in range(k)]
            tag = f"{mode}{k}".encode()
            done = [0] * k
            hashes = [[] for _ in range(k)]
            deadline = [None]

            def worker(i):
                g = gws[i]
                for r in chunks[i]:
                    if mode == "sync" and time.perf_counter() > deadline[0]:
                        break
                    did = sha256(r.data_id, tag)
                    S, R, C, E = g.analyse(r)
                    env, dek = g.protect(r, C, E)
                    ref = g.store(env)
                    h = sha256(env, ref.encode())
                    data = dep.c.data("logDecision", did, b32(r.dev_id), C, E, h, sha256(ref.encode()))
                    txh = dep.chain.submit(g.acct, dep.c.address, data, gas=300_000)
                    if mode == "sync":
                        dep.chain.wait(txh)
                        done[i] += 1
                    else:
                        hashes[i].append(txh)
                for txh in hashes[i]:
                    dep.chain.wait(txh)
                    done[i] += 1

            t0 = time.perf_counter()
            deadline[0] = t0 + SYNC_SECONDS
            th = [threading.Thread(target=worker, args=(i,)) for i in range(k)]
            [t.start() for t in th]
            [t.join() for t in th]
            wall = time.perf_counter() - t0
            tp.append({"mode": mode, "gateways": k, "records": sum(done), "wall_s": wall, "tps": sum(done) / wall})
            print(tp[-1], flush=True)
    out["e4_throughput"] = tp
    out["block_stats"] = {"max_tx_per_block": max(b[2] for b in tr.block_gas),
                          "gas_limit": tr.block_gas[-1][1],
                          "max_gas_used_fraction": max(b[0] / b[1] for b in tr.block_gas)}
    tr.stop = True
    with open(os.path.join(OUT, os.environ.get("RETH_OUT", "e2_e4_reth.json")), "w") as f:
        json.dump(out, f, indent=1)


if __name__ == "__main__":
    main()
