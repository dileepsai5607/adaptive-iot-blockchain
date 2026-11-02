"""Aggregate repeated runs into results/summary_v2.json (mean and sd across repetitions)."""
import glob
import json
import os
import statistics as st

R = os.path.join(os.path.dirname(__file__), "..", "results")


def ms(xs):
    xs = list(xs)
    return {"mean": st.mean(xs), "sd": st.pstdev(xs) if len(xs) > 1 else 0.0, "n": len(xs)}


def crypto():
    reps = [json.load(open(f)) for f in sorted(glob.glob(f"{R}/reps/e1_crypto_r*.json"))]
    nb = [json.load(open(f)) for f in sorted(glob.glob(f"{R}/reps/e1b_noaesni_r*.json"))]
    out = {"modes": {}, "paillier": {}, "noaesni": {}}
    for row in reps[0]["modes"]:
        k = f'{row["mode"]}|{row["size"]}'
        vals = [next(x for x in r["modes"] if x["mode"] == row["mode"] and x["size"] == row["size"]) for r in reps]
        out["modes"][k] = {"enc_us": ms(v["enc"]["median_us"] for v in vals), "dec_us": ms(v["dec"]["median_us"] for v in vals),
                           "ct_bytes": vals[0]["ct_bytes"]}
    P = [r["paillier"] for r in reps]
    out["paillier"] = {"keygen_ms": ms(p["keygen_ms"] for p in P),
                       "enc_ms": ms(p["encrypt"]["median_us"] / 1e3 for p in P),
                       "dec_ms": ms(p["decrypt_crt"]["median_us"] / 1e3 for p in P),
                       "add_us": ms(p["hom_add"]["median_us"] for p in P),
                       "agg1k_ms": ms(p["aggregation"][1]["aggregate_ms"] for p in P),
                       "agg10k_ms": ms(p["aggregation"][2]["aggregate_ms"] for p in P)}
    for i, row in enumerate(nb[0]["rows"]):
        out["noaesni"][row["size"]] = {"aes_sw_us": ms(n["rows"][i]["aes_gcm_sw_us"] for n in nb),
                                       "ascon_us": ms(n["rows"][i]["ascon_us"] for n in nb),
                                       "ratio": ms(n["rows"][i]["aes_gcm_sw_us"] / n["rows"][i]["ascon_us"] for n in nb)}
    return out


def chain(pattern):
    reps = [json.load(open(f)) for f in sorted(glob.glob(pattern))]
    if not reps:
        return None
    out = {"client": reps[0]["client"], "reps": len(reps), "write": {}, "read": {}, "throughput": {}}
    for m in reps[0]["e2_write"]:
        w = [r["e2_write"][m] for r in reps if m in r["e2_write"]]
        out["write"][m] = {k: ms(x[k]["median"] for x in w) for k in w[0] if isinstance(w[0][k], dict)}
        out["write"][m]["cp_p95"] = ms(x["critical_path"]["p95"] for x in w)
        out["write"][m]["count"] = ms(x["count"] for x in w)
    for m in reps[0]["e2_read"]:
        rr = [r["e2_read"][m] for r in reps if m in r["e2_read"]]
        out["read"][m] = {k: ms(x[k]["median"] for x in rr) for k in rr[0]}
    out["inclusion_all_median"] = ms(r["anchor_inclusion_all"]["median"] for r in reps)
    out["inclusion_all_p99"] = ms(r["anchor_inclusion_all"]["p99"] for r in reps)
    out["budget_met"] = ms(r["budget_met_critical_path"] for r in reps)
    out["accepted"] = ms(r["write_accepted"] for r in reps)
    for row in reps[0]["e4_throughput"]:
        k = f'{row["mode"]}|{row["gateways"]}'
        out["throughput"][k] = ms(next(x["tps"] for x in r["e4_throughput"] if x["mode"] == row["mode"]
                                       and x["gateways"] == row["gateways"]) for r in reps)
    out["block_fill_max"] = ms(r["block_stats"]["max_gas_used_fraction"] for r in reps)
    return out


def dynamic():
    f = f"{R}/e8_dynamic.json"
    if not os.path.exists(f):
        return None
    d = json.load(open(f))
    out = {}
    for pol in ("static", "adaptive"):
        runs = [r["summary"] for r in d["runs"] if r["policy"] == pol]
        out[pol] = {k: ms(r[k] for r in runs) for k in runs[0]}
    return out


if __name__ == "__main__":
    s = {"crypto": crypto(), "reth": chain(f"{R}/reps/e2_e4_reth_r*.json"),
         "besu": chain(f"{R}/reps/e2_e4_besu_r*.json"), "dynamic": dynamic()}
    for f in ("e1c_keyops.json", "e3_e5_v2.json", "e6_policy_v2.json", "e7_sensitivity.json"):
        p = f"{R}/{f}"
        s[f.split(".")[0]] = json.load(open(p)) if os.path.exists(p) else None
    json.dump(s, open(f"{R}/summary_v2.json", "w"), indent=1)
    print("summary written")
