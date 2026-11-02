"""E6: adaptive vs uniform protection policies on the same workload.
E4: write-path throughput vs number of concurrent edge gateways
(synchronous anchoring vs asynchronous anchoring)."""
import json
import os
import statistics as st
import sys
import threading
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))
import crypto_modes as cm  # noqa: E402
import edge  # noqa: E402
from env_setup import bring_up, make_gateway  # noqa: E402
from framework import b32, sha256  # noqa: E402

OUT = os.path.join(os.path.dirname(__file__), "..", "results")
N = int(os.environ.get("N_POLICY", 2000))
N_TP = int(os.environ.get("N_TP", 1200))

# Functional requirements per data type, fixed before running (Sec. on evaluation design):
#  - confidentiality floor: the on-chain min class and allowed modes
#  - pseudonymisation needed where identifiers must stay linkable without being revealed (Medium streams)
#  - encrypted aggregation needed for the daily wearable stream (population statistics)
NEEDS_PSEUDONYM = {"smart_meter"}
NEEDS_AGGREGATION = {"wearable_daily"}


def run_policies(gw):
    recs = edge.generate(N, seed=21)
    policies = ["Adaptive", "Uniform-None", "Uniform-ASCON", "Uniform-AES", "Uniform-AES+PHE"]
    res = {}
    # For Uniform-AES+PHE every numeric field of every record is Paillier-encrypted
    for pol in policies:
        lat, size, comp, cap, budget_ok = [], 0, 0, 0, 0
        for r in recs:
            t0 = time.perf_counter()
            S, R, C, E = gw.analyse(r)
            if pol != "Adaptive":
                E = {"Uniform-None": cm.NONE, "Uniform-ASCON": cm.ASCON, "Uniform-AES": cm.AES,
                     "Uniform-AES+PHE": cm.AES_PHE}[pol]
            prof = edge.PROFILES[r.dtype]
            saved = prof["phe"]
            if pol == "Uniform-AES+PHE":
                prof["phe"] = [k for k, v in r.payload.items() if isinstance(v, (int, float)) and not isinstance(v, bool)]
            try:
                env, _ = gw.protect(r, C, E)
            finally:
                prof["phe"] = saved
            ref = gw.store(env)
            sha256(env, ref.encode())
            dt = (time.perf_counter() - t0) * 1000
            lat.append(dt)
            size += len(env)
            ok = C >= edge.MIN_CLASS[r.dtype] and (edge.ALLOWED[C] >> E) & 1
            comp += bool(ok)
            need_ok = True
            if r.dtype in NEEDS_PSEUDONYM and C == edge.MEDIUM and E != cm.AES_MASK:
                need_ok = False
            if r.dtype in NEEDS_AGGREGATION and E != cm.AES_PHE:
                need_ok = False
            cap += need_ok
            budget_ok += dt <= r.budget_ms
        lat.sort()
        res[pol] = {"mean_ms": st.mean(lat), "p95_ms": lat[int(0.95 * len(lat)) - 1], "total_cpu_s": sum(lat) / 1000,
                    "bytes_total": size, "policy_compliance": comp / N, "requirement_coverage": cap / N,
                    "latency_budget_met": budget_ok / N}
        print(pol, {k: round(v, 4) for k, v in res[pol].items()})
    return res


def run_throughput(dep, krs, pub, sql, ipfs):
    res = []
    base = edge.generate(N_TP * 2, seed=31)
    # throughput runs use telemetry only (no CCTV frames) to isolate chain/pipeline cost
    pool = [r for r in base if r.dtype != "cctv_frame"][:N_TP]
    for mode in ("sync", "async"):
        for k in (1, 2, 4, 8):
            gws = [make_gateway(dep, krs, pub, sql, ipfs, idx=i) for i in range(k)]
            chunks = [pool[i::k] for i in range(k)]
            # fresh dataIds per run so nothing is rejected as a duplicate
            for ch in chunks:
                for r in ch:
                    r.data_id = sha256(r.data_id, f"{mode}{k}".encode())
            done = [0] * k

            def worker(i):
                g = gws[i]
                hashes = []
                for r in chunks[i]:
                    S, R, C, E = g.analyse(r)
                    env, dek = g.protect(r, C, E)
                    ref = g.store(env)
                    h = sha256(env, ref.encode())
                    data = dep.c.data("logDecision", r.data_id, b32(r.dev_id), C, E, h, sha256(ref.encode()))
                    if mode == "sync":
                        dep.chain.send(g.acct, dep.c.address, data, gas=400_000)
                    else:
                        hashes.append(dep.chain.submit(g.acct, dep.c.address, data, gas=400_000))
                for hh in hashes:
                    dep.chain.wait(hh)
                done[i] = len(chunks[i])

            t0 = time.perf_counter()
            th = [threading.Thread(target=worker, args=(i,)) for i in range(k)]
            [t.start() for t in th]
            [t.join() for t in th]
            wall = time.perf_counter() - t0
            res.append({"mode": mode, "gateways": k, "records": sum(done), "wall_s": wall, "tps": sum(done) / wall})
            print(res[-1])
    return res


def main():
    dep, krs, pub, sql, ipfs = bring_up(port=8546)
    gw = make_gateway(dep, krs, pub, sql, ipfs)
    out = {"e6_policies": run_policies(gw)}
    if not os.environ.get("ONLY_POLICY"):
        # Anvil-based throughput (superseded by bench_reth.py; kept for reference)
        out["e4_throughput_anvil"] = run_throughput(dep, krs, pub, sql, ipfs)
    with open(os.path.join(OUT, "e6_policy.json" if os.environ.get("ONLY_POLICY") else "e4_e6.json"), "w") as f:
        json.dump(out, f, indent=1)


if __name__ == "__main__":
    main()
