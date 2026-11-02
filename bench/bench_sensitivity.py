"""E7: sensitivity of the decision engine to its hand-set parameters.

Varies the sensitivity weights (Eq. 1), the class thresholds (Eq. 3), R_min and
L_PHE on a fixed 5,000-record workload and reports, per configuration:
  agreement   - share of records whose class equals the default configuration's
  below_floor - share whose class falls below the on-chain floor (would be rejected)
  phe_share   - share protected with AES+PHE
  coverage    - functional-requirement coverage (as in E6)
  cost_ms     - mean protection cost, from per-mode mean encryption cost measured in E2
The gateway's CPU/memory terms are fixed (c=0.8, m=0.9) so results are deterministic."""
import itertools
import json
import os
import random
import statistics as st
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))
import crypto_modes as cm  # noqa: E402
import edge  # noqa: E402

R = os.path.join(os.path.dirname(__file__), "..", "results")
N = 5000
W0 = (0.4, 0.2, 0.2, 0.2)
GW_C, GW_M = 0.8, 0.9   # nominal gateway headroom; mains-powered (b = 1)

import glob  # noqa: E402
_reps = [json.load(open(f)) for f in sorted(glob.glob(os.path.join(R, "reps", "e2_e4_reth_r*.json")))]
COST = {cm.NONE: 0.0, cm.ASCON: 0.0, cm.AES_MASK: 0.0, cm.AES: 0.0, cm.AES_PHE: 0.0}
for name in _reps[0]["e2_write"]:
    mode = {n: k for k, n in cm.MODE_NAMES.items()}[name]
    COST[mode] = st.mean(r["e2_write"][name]["encrypt"]["mean"] for r in _reps)


def components(r):
    p = edge.PROFILES[r.dtype]
    return (p["s_type"], edge.context_score(r.dtype, r.payload), edge.DOMAIN_SCORE[p["domain"]], p["reg"])


def decide(r, comp, w, th, tm, rmin, lphe, clamp):  # noqa: C901
    S = sum(wi * ci for wi, ci in zip(w, comp))
    C = edge.HIGH if S >= th else edge.MEDIUM if S >= tm else edge.LOW
    floor = edge.MIN_CLASS[r.dtype]
    below = C < floor
    if clamp:
        C = max(C, floor)
    R_ = edge.resource_score(GW_C, GW_M, 1.0, r.net)
    p = edge.PROFILES[r.dtype]
    if C == edge.HIGH:
        E = cm.AES if (r.rt == 1 or R_ < rmin or r.budget_ms < lphe or not p["phe"]) else cm.AES_PHE
    elif C == edge.MEDIUM:
        E = cm.AES_MASK if p["ids"] else cm.AES
    else:
        E = cm.NONE if p["public"] else cm.ASCON
    return C, E, below


def evaluate(recs, comps, base, w=W0, th=80, tm=40, rmin=edge.R_MIN, lphe=500, clamp=False):
    agree = below = phe = cover = above = 0
    cost = []
    for r, comp, b in zip(recs, comps, base):
        C, E, bl = decide(r, comp, w, th, tm, rmin, lphe, clamp)
        agree += C == b
        below += bl
        above += C > edge.MIN_CLASS[r.dtype]
        phe += E == cm.AES_PHE
        ok = True
        if r.dtype == "smart_meter" and C == edge.MEDIUM and E != cm.AES_MASK:
            ok = False
        if r.dtype == "wearable_daily" and E != cm.AES_PHE:
            ok = False
        if bl and not clamp:
            ok = False          # would be rejected on-chain
        cover += ok
        cost.append(COST[E])
    n = len(recs)
    return {"agreement": agree / n, "below_floor": below / n, "phe_share": phe / n, "coverage": cover / n,
            "cost_ms": st.mean(cost), "escalated": above / n}


def renorm(w):
    s = sum(w)
    return tuple(x / s for x in w)


def main():
    recs = edge.generate(N, seed=41)
    comps = [components(r) for r in recs]
    base = [decide(r, c, W0, 80, 40, edge.R_MIN, 500, False)[0] for r, c in zip(recs, comps)]
    out = {"default": evaluate(recs, comps, base), "default_clamped": evaluate(recs, comps, base, clamp=True)}

    # (a) one-at-a-time weight perturbation (+/-0.1, others rescaled to keep sum 1)
    oat = []
    names = ["w_type", "w_ctx", "w_dom", "w_reg"]
    for i, d in itertools.product(range(4), (-0.1, +0.1)):
        w = list(W0)
        w[i] = W0[i] + d
        rest = 1 - w[i]
        others = [j for j in range(4) if j != i]
        tot = sum(W0[j] for j in others)
        for j in others:
            w[j] = W0[j] / tot * rest
        res = evaluate(recs, comps, base, w=tuple(w))
        res_c = evaluate(recs, comps, base, w=tuple(w), clamp=True)
        oat.append({"param": names[i], "delta": d, "w": w, **res, "clamped": res_c})
    out["weights_oat"] = oat

    # (b) random weights from a Dirichlet centred on W0 (concentration 50)
    rng = random.Random(5)
    rnd = []
    for _ in range(1000):
        g = [rng.gammavariate(50 * a, 1) for a in W0]
        w = renorm(g)
        rnd.append({"w": w, **evaluate(recs, comps, base, w=w), "clamped": evaluate(recs, comps, base, w=w, clamp=True)})
    out["weights_random"] = {
        "n": len(rnd),
        "max_abs_dev": max(max(abs(a - b) for a, b in zip(x["w"], W0)) for x in rnd),
        "agreement": {"min": min(x["agreement"] for x in rnd), "median": st.median(x["agreement"] for x in rnd)},
        "below_floor": {"max": max(x["below_floor"] for x in rnd), "share_configs_nonzero": sum(x["below_floor"] > 0 for x in rnd) / len(rnd)},
        "cost_ms": {"min": min(x["cost_ms"] for x in rnd), "max": max(x["cost_ms"] for x in rnd)},
        "clamped_coverage_min": min(x["clamped"]["coverage"] for x in rnd),
        "clamped_below_floor_max": max(x["clamped"]["below_floor"] for x in rnd),
        "clamped_agreement_min": min(x["clamped"]["agreement"] for x in rnd),
        "clamped_cost_ms": {"min": min(x["clamped"]["cost_ms"] for x in rnd), "max": max(x["clamped"]["cost_ms"] for x in rnd)},
        "clamped_escalated": {"min": min(x["clamped"]["escalated"] for x in rnd), "max": max(x["clamped"]["escalated"] for x in rnd)},
    }

    # (c) threshold grid
    grid = []
    for th, tm in itertools.product((70, 75, 80, 85, 90), (30, 35, 40, 45, 50)):
        res = evaluate(recs, comps, base, th=th, tm=tm)
        res_c = evaluate(recs, comps, base, th=th, tm=tm, clamp=True)
        grid.append({"T_high": th, "T_med": tm, **res, "clamped": res_c})
    out["thresholds"] = grid

    # (d) R_min and L_PHE
    rl = []
    for rmin, lphe in itertools.product((0.4, 0.5, 0.6, 0.7, 0.8), (100, 500, 1000, 5000, 20000)):
        rl.append({"R_min": rmin, "L_PHE": lphe, **evaluate(recs, comps, base, rmin=rmin, lphe=lphe)})
    out["rmin_lphe"] = rl

    with open(os.path.join(R, "e7_sensitivity.json"), "w") as f:
        json.dump(out, f, indent=1)

    print("default", out["default"])
    print("default clamped", out["default_clamped"])
    for x in oat:
        print(f"{x['param']} {x['delta']:+.1f} agree {x['agreement']:.3f} below {x['below_floor']:.3f} "
              f"cov {x['coverage']:.3f} cost {x['cost_ms']:.2f} | clamped cov {x['clamped']['coverage']:.3f} "
              f"cost {x['clamped']['cost_ms']:.2f}")
    print("random", out["weights_random"])
    for g in grid:
        print(f"T_high {g['T_high']} T_med {g['T_med']} agree {g['agreement']:.3f} below {g['below_floor']:.3f} "
              f"cov {g['coverage']:.3f} cost {g['cost_ms']:.2f} | clamped cov {g['clamped']['coverage']:.3f} cost {g['clamped']['cost_ms']:.2f}")
    for x in rl:
        print(f"R_min {x['R_min']} L_PHE {x['L_PHE']} phe {x['phe_share']:.3f} cov {x['coverage']:.3f} cost {x['cost_ms']:.2f}")


if __name__ == "__main__":
    main()
