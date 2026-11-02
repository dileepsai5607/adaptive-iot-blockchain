"""E6: adaptive vs uniform protection policies on the same workload (off-chain write path; on-chain
anchoring costs the same in every mode). Gateway at nominal load (CPU headroom 0.8, mains power).
Repeated over three workload seeds; reports mean and standard deviation."""
import json
import os
import statistics as st
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))
import crypto_modes as cm  # noqa: E402
import edge  # noqa: E402
from framework import Gateway, sha256  # noqa: E402
from storage import SQLStore, start_ipfs  # noqa: E402

OUT = os.path.join(os.path.dirname(__file__), "..", "results")
N = int(os.environ.get("N_POLICY", 2000))
POLICIES = ["Uniform-None", "Uniform-ASCON", "Uniform-AES", "Uniform-AES+PHE", "Adaptive"]
FORCE = {"Uniform-None": cm.NONE, "Uniform-ASCON": cm.ASCON, "Uniform-AES": cm.AES, "Uniform-AES+PHE": cm.AES_PHE}


class NullKRS:
    def deposit(self, *a):
        pass


def run_seed(seed, gw):
    recs = edge.generate(N, seed=seed)
    res = {}
    for pol in POLICIES:
        lat, size, comp, cov, bud = [], 0, 0, 0, 0
        for r in recs:
            t0 = time.perf_counter()
            S, R, C, E = gw.analyse(r)
            if pol in FORCE:
                E = FORCE[pol]
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
            dt = (time.perf_counter() - t0) * 1e3
            lat.append(dt)
            size += len(env)
            ok = C >= edge.MIN_CLASS[r.dtype] and (edge.ALLOWED[C] >> E) & 1
            comp += bool(ok)
            need = True
            if r.dtype == "smart_meter" and C == edge.MEDIUM and E != cm.AES_MASK:
                need = False
            if r.dtype == "wearable_daily" and E != cm.AES_PHE:
                need = False
            cov += need
            bud += dt <= r.budget_ms
        lat.sort()
        res[pol] = {"mean_ms": st.mean(lat), "p95_ms": lat[int(.95 * len(lat)) - 1], "cpu_s": sum(lat) / 1e3,
                    "MB": size / 1e6, "compliance": comp / N, "coverage": cov / N, "budget": bud / N}
    return res


if __name__ == "__main__":
    ipfs_p, ipfs = start_ipfs(os.path.join(OUT, "..", "run", "ipfs-policy"))
    phe_pub, _ = cm.paillier_keygen(2048)
    sql = SQLStore(":memory:")
    gw = Gateway(None, None, NullKRS(), phe_pub, sql, ipfs, load_fn=lambda: (0.8, 0.9, 1.0))
    seeds = [21, 22, 23]
    runs = [run_seed(s, gw) for s in seeds]
    summary = {p: {k: {"mean": st.mean(r[p][k] for r in runs), "sd": st.pstdev(r[p][k] for r in runs)}
                   for k in runs[0][p]} for p in POLICIES}
    json.dump({"seeds": seeds, "runs": runs, "summary": summary}, open(os.path.join(OUT, "e6_policy_v2.json"), "w"),
              indent=1)
    for p in POLICIES:
        print(p, {k: f"{v['mean']:.4f}±{v['sd']:.4f}" for k, v in summary[p].items()})
    ipfs_p.kill()
