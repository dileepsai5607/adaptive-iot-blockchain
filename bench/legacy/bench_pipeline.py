"""E2 end-to-end stage latency, E3 gas, E5 security tests, storage comparison."""
import json
import os
import random
import statistics as st
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))
import crypto_modes as cm  # noqa: E402
import edge  # noqa: E402
from chain import Contract  # noqa: E402
from env_setup import bring_up, make_gateway  # noqa: E402
from framework import Client, b32, sha256  # noqa: E402

OUT = os.path.join(os.path.dirname(__file__), "..", "results")
N_WRITE = int(os.environ.get("N_WRITE", 2000))
N_READ = int(os.environ.get("N_READ", 600))
TRIALS = int(os.environ.get("TRIALS", 100))


def summarize(xs):
    xs = sorted(xs)
    return {"n": len(xs), "mean": st.mean(xs), "median": st.median(xs), "p95": xs[max(0, int(0.95 * len(xs)) - 1)],
            "std": st.pstdev(xs)}


def main():
    dep, krs, pub, sql, ipfs = bring_up()
    gw = make_gateway(dep, krs, pub, sql, ipfs)
    out = {"deploy_gas": dep.deploy_gas, "admin_gas": None}

    # ---------------- E2: write path ----------------
    recs = edge.generate(N_WRITE, seed=11)
    writes = []
    for r in recs:
        x = gw.ingest(r)
        x["dtype"] = r.dtype
        x["budget"] = r.budget_ms
        writes.append(x)
    assert all(w["accepted"] for w in writes)
    stages_w = ["edge_analysis", "encrypt", "store", "hash", "chain_anchor"]
    by_mode = {}
    for w in writes:
        by_mode.setdefault(cm.MODE_NAMES[w["E"]], []).append(w)
    e2w = {}
    for m, ws in by_mode.items():
        e2w[m] = {s: summarize([w["t"][s] for w in ws]) for s in stages_w}
        e2w[m]["total"] = summarize([sum(w["t"].values()) for w in ws])
        e2w[m]["off_chain"] = summarize([sum(v for k, v in w["t"].items() if k != "chain_anchor") for w in ws])
        e2w[m]["env_bytes"] = summarize([w["size"] for w in ws])
        e2w[m]["count"] = len(ws)
        e2w[m]["gas"] = summarize([w["gas"] for w in ws])
    out["e2_write"] = e2w
    out["decision_matrix"] = {}
    for w in writes:
        k = f"{w['dtype']}|{edge.CLASS_NAMES[w['C']]}|{cm.MODE_NAMES[w['E']]}"
        out["decision_matrix"][k] = out["decision_matrix"].get(k, 0) + 1
    out["budget_met_offchain"] = sum(
        1 for w in writes if sum(v for k, v in w["t"].items() if k != "chain_anchor") <= w["budget"]) / len(writes)
    print("write done", {m: round(v["total"]["median"], 2) for m, v in e2w.items()})

    # ---------------- E2: read path ----------------
    admin = Client(dep, dep.register_user(0, "Admin"), gw, krs)
    rng = random.Random(3)
    sample = rng.sample(list(zip(recs, writes)), N_READ)
    reads = {}
    for r, w in sample:
        status, pt, t, gas = admin.retrieve(r.data_id)
        assert status == "OK", status
        reads.setdefault(cm.MODE_NAMES[w["E"]], []).append((t, gas))
    stages_r = ["access_request", "fetch", "chain_read", "verify", "decrypt"]
    out["e2_read"] = {m: {**{s: summarize([t[s] for t, _ in v]) for s in stages_r},
                          "total": summarize([sum(t.values()) for t, _ in v]),
                          "gas": summarize([g for _, g in v])} for m, v in reads.items()}
    print("read done", {m: round(v["total"]["median"], 2) for m, v in out["e2_read"].items()})

    # ---------------- Storage backend comparison ----------------
    stor = []
    for size in [256, 1024, 4096, 16384, 65536, 262144]:
        blob = os.urandom(size)
        for backend in ("sqlite", "ipfs"):
            put, get = [], []
            for _ in range(60):
                import time
                t0 = time.perf_counter()
                ref = sql.put(blob) if backend == "sqlite" else ipfs.add(blob)
                put.append((time.perf_counter() - t0) * 1000)
                t0 = time.perf_counter()
                sql.get(ref) if backend == "sqlite" else ipfs.cat(ref)
                get.append((time.perf_counter() - t0) * 1000)
            stor.append({"backend": backend, "size": size, "put": summarize(put), "get": summarize(get)})
    out["storage"] = stor
    print("storage done")

    # ---------------- E5: security tests ----------------
    sec = {}
    pool = [(r, w) for r, w in zip(recs, writes)]

    # (1) Unauthorized access
    unreg = Client(dep, dep.register_user(1, None), gw, krs)
    nurse = Client(dep, dep.register_user(2, "Nurse"), gw, krs)
    analyst = Client(dep, dep.register_user(3, "Analyst"), gw, krs)
    doctor = Client(dep, dep.register_user(4, "Doctor"), gw, krs)
    picks = rng.sample(pool, TRIALS)
    sec["unregistered_user"] = sum(unreg.retrieve(r.data_id)[0] == "DENIED" for r, _ in picks) / TRIALS
    non_icu = [p for p in pool if p[0].dtype not in ("icu_monitor",)]
    sec["wrong_role_nurse"] = sum(nurse.retrieve(r.data_id)[0] == "DENIED" for r, _ in rng.sample(non_icu, TRIALS)) / TRIALS
    health = [p for p in pool if p[0].dtype in ("icu_monitor",)]
    sec["wrong_role_analyst_icu"] = sum(analyst.retrieve(r.data_id)[0] == "DENIED" for r, _ in rng.sample(health, TRIALS)) / TRIALS
    sec["authorized_doctor_success"] = sum(doctor.retrieve(r.data_id)[0] == "OK" for r, _ in rng.sample(health, TRIALS)) / TRIALS

    # (2) Key-release abuse: replayed grant, stolen grant
    enc_pool = [p for p in pool if p[1]["E"] != cm.NONE and p[0].dtype in ("icu_monitor", "wearable_daily")]
    replay_block, steal_block = 0, 0
    for r, _ in rng.sample(enc_pool, TRIALS):
        rc = dep.c.tx(doctor.acct, "requestAccess", r.data_id)
        h = rc["transactionHash"]
        assert krs.release(r.data_id, doctor.acct, doctor.pk, h) is not None
        replay_block += krs.release(r.data_id, doctor.acct, doctor.pk, h) is None
        rc2 = dep.c.tx(doctor.acct, "requestAccess", r.data_id)
        steal_block += krs.release(r.data_id, unreg.acct, unreg.pk, rc2["transactionHash"]) is None
    sec["krs_replay_blocked"] = replay_block / TRIALS
    sec["krs_stolen_grant_blocked"] = steal_block / TRIALS

    # (3) Tampering in off-chain storage
    sql_pool = [p for p in pool if p[1]["ref"].startswith("sqlite") and p[1]["E"] != cm.NONE]
    none_pool = [p for p in pool if p[1]["ref"].startswith("sqlite") and p[1]["E"] == cm.NONE]
    ipfs_pool = [p for p in pool if p[1]["ref"].startswith("ipfs")]

    def bitflip_ct(blob):
        env = json.loads(blob)
        ct = bytearray(__import__("base64").b64decode(env["ct"]))
        ct[rng.randrange(len(ct))] ^= 1 << rng.randrange(8)
        env["ct"] = __import__("base64").b64encode(bytes(ct)).decode()
        return json.dumps(env, sort_keys=True, separators=(",", ":")).encode()

    def meta_edit(blob):
        env = json.loads(blob)
        env["h"]["ts"] = env["h"]["ts"] + 1
        return json.dumps(env, sort_keys=True, separators=(",", ":")).encode()

    def plaintext_edit(blob):   # mode None: attacker edits a public reading
        env = json.loads(blob)
        body = json.loads(__import__("base64").b64decode(env["ct"]))
        body["temp_c"] = body.get("temp_c", 0) + 5
        env["ct"] = __import__("base64").b64encode(json.dumps(body).encode()).decode()
        return json.dumps(env, sort_keys=True, separators=(",", ":")).encode()

    for name, pool_, fn in (("tamper_ciphertext_bitflip", sql_pool, bitflip_ct),
                            ("tamper_metadata_edit", sql_pool, meta_edit),
                            ("tamper_plaintext_none_mode", none_pool, plaintext_edit)):
        det = 0
        for r, w in rng.sample(pool_, TRIALS):
            orig = sql.get(w["ref"])
            sql.overwrite(w["ref"], fn(orig))
            det += admin.retrieve(r.data_id)[0] == "TAMPER"
            sql.overwrite(w["ref"], orig)
        sec[name] = det / TRIALS

    # Index substitution: point dataId to another valid object; and forge a new IPFS object
    det_sub, det_forge = 0, 0
    for r, w in rng.sample(pool, TRIALS):
        other = rng.choice(pool)[1]["ref"]
        orig = gw.index[r.data_id]
        gw.index[r.data_id] = other
        det_sub += admin.retrieve(r.data_id)[0] == "TAMPER"
        gw.index[r.data_id] = orig
    for r, w in rng.sample(ipfs_pool, min(TRIALS, len(ipfs_pool))):
        orig = gw.index[r.data_id]
        forged = bitflip_ct(admin.fetch(orig))
        gw.index[r.data_id] = "ipfs:" + ipfs.add(forged)
        det_forge += admin.retrieve(r.data_id)[0] == "TAMPER"
        gw.index[r.data_id] = orig
    sec["tamper_reference_substitution"] = det_sub / TRIALS
    sec["tamper_ipfs_forged_object"] = det_forge / min(TRIALS, len(ipfs_pool))

    # (4) Malicious edge: downgrade / mislabel / replay / unknown device
    def attempt(rec, C, E):
        return gw.ingest(rec, override=(C, E))
    fresh = edge.generate(TRIALS * 6, seed=999)
    icu = [r for r in fresh if r.dtype == "icu_monitor"][:TRIALS]
    met = [r for r in fresh if r.dtype == "smart_meter"][:TRIALS]
    sec["downgrade_icu_to_low_none"] = sum(not attempt(r, edge.LOW, cm.NONE)["accepted"] for r in icu) / len(icu)
    sec["downgrade_icu_high_with_mask"] = sum(not attempt(r, edge.HIGH, cm.AES_MASK)["accepted"] for r in icu) / len(icu)
    sec["downgrade_meter_to_low_ascon"] = sum(not attempt(r, edge.LOW, cm.ASCON)["accepted"] for r in met) / len(met)
    reps = rng.sample(recs, TRIALS)
    sec["replay_duplicate_dataid"] = sum(not gw.ingest(r)["accepted"] for r in reps) / TRIALS
    rej_gas = []
    unk = 0
    for r in rng.sample(fresh, TRIALS):
        r.dev_id = "rogue-" + r.dev_id
        x = gw.ingest(r)
        unk += not x["accepted"]
        rej_gas.append(x["gas"])
    sec["unknown_device"] = unk / TRIALS
    # unauthorised account trying to log
    rc = Contract(dep.chain, dep.c.address, dep.art["AdaptiveTrust"]["hashes"]).tx(
        unreg.acct, "logDecision", os.urandom(32), b32("icu_monitor-00"), 2, 3, os.urandom(32), os.urandom(32))
    sec["non_edge_account_reverted"] = 1.0 if int(rc["status"], 16) == 0 else 0.0
    out["e5_security"] = sec
    print("security", sec)

    # ---------------- E3: gas ----------------
    gas = {"deploy_AdaptiveTrust": dep.deploy_gas, **{f"admin_{k}": v for k, v in dep.admin_gas.items()}}
    gas["logDecision_accepted"] = summarize([w["gas"] for w in writes])
    gas["logDecision_rejected"] = summarize(rej_gas)
    rc_g = dep.c.tx(doctor.acct, "requestAccess", health[0][0].data_id)
    rc_d = dep.c.tx(unreg.acct, "requestAccess", health[0][0].data_id)
    rc_t = dep.c.tx(doctor.acct, "reportTamper", health[0][0].data_id, os.urandom(32))
    gas["requestAccess_granted"] = int(rc_g["gasUsed"], 16)
    gas["requestAccess_denied"] = int(rc_d["gasUsed"], 16)
    gas["reportTamper"] = int(rc_t["gasUsed"], 16)

    # Naive baseline (string-typed, two transactions per record)
    naddr, nrc = dep.chain.deploy(dep.owner, dep.art["NaiveTrust"]["bin"])
    naive = Contract(dep.chain, naddr, dep.art["NaiveTrust"]["hashes"])
    gas["deploy_NaiveTrust"] = int(nrc["gasUsed"], 16)
    naive.tx(dep.owner, "setPolicy", "High", "AES")
    naive.tx(dep.owner, "setPolicy", "Medium", "AES+Mask")
    naive.tx(dep.owner, "setPolicy", "Low", "Lightweight")
    nv, nh = [], []
    cls_name = {0: "Low", 1: "Medium", 2: "High"}
    mode_name = {0: "Lightweight", 1: "Lightweight", 2: "AES+Mask", 3: "AES", 4: "AES"}
    for w, r in zip(writes[:300], recs[:300]):
        a = naive.tx(dep.owner, "validateDecision", r.data_id, cls_name[w["C"]], mode_name[w["E"]])
        ref = w["ref"] if w["ref"].startswith("ipfs") else "ipfs:bafkreigh2akiscaildcqabsyg3dfr6chu3fgpregiymsck7e7aqa4s52zy"
        b = naive.tx(dep.owner, "logHash", r.data_id, sha256(r.data_id), ref)
        nv.append(int(a["gasUsed"], 16))
        nh.append(int(b["gasUsed"], 16))
    gas["naive_validateDecision"] = summarize(nv)
    gas["naive_logHash"] = summarize(nh)
    gas["naive_per_record_total"] = summarize([a + b for a, b in zip(nv, nh)])
    out["e3_gas"] = gas
    print("gas", {k: (v if isinstance(v, int) else round(v["mean"])) for k, v in gas.items()})

    with open(os.path.join(OUT, "e2_e3_e5.json"), "w") as f:
        json.dump(out, f, indent=1)


if __name__ == "__main__":
    main()
