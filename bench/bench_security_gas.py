"""E3 gas (incl. same-chain baselines), E5 security tests (incl. non-conformance and threshold
KRS failures), and KRS read-path overhead (centralized 1-of-1 vs threshold 2-of-3).
Runs on Anvil (instant mining); gas is client-independent."""
import json
import os
import random
import statistics as st
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))
import crypto_modes as cm  # noqa: E402
import edge  # noqa: E402
import threshold as th  # noqa: E402
from chain import Contract  # noqa: E402
from env_setup import bring_up, make_gateway  # noqa: E402
from framework import Client, b32, sha256  # noqa: E402

OUT = os.path.join(os.path.dirname(__file__), "..", "results")
N_WRITE = int(os.environ.get("N_WRITE", 1500))
TRIALS = int(os.environ.get("TRIALS", 100))


def summ(xs):
    xs = sorted(xs)
    return {"n": len(xs), "mean": st.mean(xs), "median": st.median(xs), "p95": xs[max(0, int(.95 * len(xs)) - 1)]}


def main():
    dep, krs, pub, sql, ipfs = bring_up(port=8545)
    gw = make_gateway(dep, krs, pub, sql, ipfs)
    rng = random.Random(3)
    recs = edge.generate(N_WRITE, seed=11)
    writes = [gw.ingest(r) for r in recs]
    assert all(w["accepted"] for w in writes)
    pool = list(zip(recs, writes))
    out = {"deploy_gas": dep.deploy_gas}

    admin = Client(dep, dep.register_user(0, "Admin"), gw, krs)
    unreg = Client(dep, dep.register_user(1, None), gw, krs)
    nurse = Client(dep, dep.register_user(2, "Nurse"), gw, krs)
    analyst = Client(dep, dep.register_user(3, "Analyst"), gw, krs)
    doctor = Client(dep, dep.register_user(4, "Doctor"), gw, krs)

    # ---------------- KRS read-path overhead (threshold 2-of-3, hybrid wrap) ----------------
    ov = {}
    for m in (cm.ASCON, cm.AES, cm.AES_PHE):
        sel = [r for r, w in pool if w["E"] == m][:60]
        ts = [admin.retrieve(r.data_id)[2] for r in sel]
        ov[cm.MODE_NAMES[m]] = {k: summ([t.get(k, 0) for t in ts]) for k in ("key_release", "key_combine", "decrypt")}
    out["krs_overhead_threshold"] = ov

    # ---------------- E5 security ----------------
    sec = {}
    picks = rng.sample(pool, TRIALS)
    sec["A2_unregistered"] = sum(unreg.retrieve(r.data_id)[0] == "DENIED" for r, _ in picks) / TRIALS
    non_icu = [p for p in pool if p[0].dtype != "icu_monitor"]
    sec["A2_nurse_wrong_role"] = sum(nurse.retrieve(r.data_id)[0] == "DENIED" for r, _ in rng.sample(non_icu, TRIALS)) / TRIALS
    icu = [p for p in pool if p[0].dtype == "icu_monitor"]
    sec["A2_analyst_icu"] = sum(analyst.retrieve(r.data_id)[0] == "DENIED" for r, _ in rng.sample(icu, TRIALS)) / TRIALS
    sec["control_doctor_ok"] = sum(doctor.retrieve(r.data_id)[0] == "OK" for r, _ in rng.sample(icu, TRIALS)) / TRIALS

    enc = [p for p in pool if p[1]["E"] != cm.NONE and p[0].dtype in ("icu_monitor", "wearable_daily")]
    replay = steal = 0
    for r, _ in rng.sample(enc, TRIALS):
        rc = dep.c.tx(doctor.acct, "requestAccess", r.data_id)
        h = rc["transactionHash"]
        assert krs.release(r.data_id, doctor.acct, doctor.pub, h) is not None
        replay += krs.release(r.data_id, doctor.acct, doctor.pub, h) is None
        rc2 = dep.c.tx(doctor.acct, "requestAccess", r.data_id)
        steal += krs.release(r.data_id, unreg.acct, unreg.pub, rc2["transactionHash"]) is None
    sec["A4_replayed_grant"] = replay / TRIALS
    sec["A4_stolen_grant"] = steal / TRIALS

    # threshold KRS: a single compromised node's share reveals nothing; one node offline is tolerated
    one_share = ok_offline = fail_two_offline = 0
    for r, w in rng.sample(enc, TRIALS):
        x, y = krs.nodes[0]._share(r.data_id)
        h_kc = json.loads(gw.fetch(w["ref"]))["h"]["kc"]
        from framework import key_commit
        one_share += key_commit(r.data_id, th.shamir_combine([(x, y)], 32)) != h_kc
    for r, _ in rng.sample(enc, TRIALS // 2):
        krs.nodes[1].online = False
        ok_offline += doctor.retrieve(r.data_id)[0] == "OK"
        krs.nodes[2].online = False
        fail_two_offline += doctor.retrieve(r.data_id)[0] == "KEY_REFUSED"
        krs.nodes[1].online = krs.nodes[2].online = True
    sec["KRS_single_share_useless"] = one_share / TRIALS
    sec["KRS_one_node_offline_served"] = ok_offline / (TRIALS // 2)
    sec["KRS_two_nodes_offline_refused"] = fail_two_offline / (TRIALS // 2)

    # storage tampering (A1)
    sqlp = [p for p in pool if p[1]["ref"].startswith("sqlite") and p[1]["E"] != cm.NONE]
    nonep = [p for p in pool if p[1]["ref"].startswith("sqlite") and p[1]["E"] == cm.NONE]
    ipfsp = [p for p in pool if p[1]["ref"].startswith("ipfs")]
    import base64

    def reenc(env):
        return json.dumps(env, sort_keys=True, separators=(",", ":")).encode()

    def flip(blob):
        env = json.loads(blob)
        ct = bytearray(base64.b64decode(env["ct"]))
        ct[rng.randrange(len(ct))] ^= 1 << rng.randrange(8)
        env["ct"] = base64.b64encode(bytes(ct)).decode()
        return reenc(env)

    def meta(blob):
        env = json.loads(blob)
        env["h"]["ts"] += 1
        return reenc(env)

    def ptedit(blob):
        env = json.loads(blob)
        body = json.loads(base64.b64decode(env["ct"]))
        body["temp_c"] = body.get("temp_c", 0) + 5
        env["ct"] = base64.b64encode(json.dumps(body).encode()).decode()
        return reenc(env)
    for name, pl, fn in (("A1_ciphertext_bitflip", sqlp, flip), ("A1_metadata_edit", sqlp, meta),
                         ("A1_open_data_edit", nonep, ptedit)):
        det = 0
        for r, w in rng.sample(pl, TRIALS):
            orig = sql.get(w["ref"])
            sql.overwrite(w["ref"], fn(orig))
            det += admin.retrieve(r.data_id)[0] == "TAMPER"
            sql.overwrite(w["ref"], orig)
        sec[name] = det / TRIALS
    det_sub = det_forge = 0
    for r, w in rng.sample(pool, TRIALS):
        orig = gw.index[r.data_id]
        gw.index[r.data_id] = rng.choice(pool)[1]["ref"]
        det_sub += admin.retrieve(r.data_id)[0] == "TAMPER"
        gw.index[r.data_id] = orig
    nf = min(TRIALS, len(ipfsp))
    for r, w in rng.sample(ipfsp, nf):
        orig = gw.index[r.data_id]
        gw.index[r.data_id] = "ipfs:" + ipfs.add(flip(gw.fetch(orig)))
        det_forge += admin.retrieve(r.data_id)[0] == "TAMPER"
        gw.index[r.data_id] = orig
    sec["A1_index_substitution"] = det_sub / TRIALS
    sec["A1_forged_ipfs_object"] = det_forge / nf

    # malicious gateway (A3): declared downgrades, replay, unknown device, non-gateway caller
    fresh = edge.generate(TRIALS * 30, seed=999)
    icu_f = [r for r in fresh if r.dtype == "icu_monitor"]
    met_f = [r for r in fresh if r.dtype == "smart_meter"][:TRIALS]
    assert len(icu_f) >= 2 * TRIALS and len(met_f) == TRIALS
    sec["A3_icu_as_low_none"] = sum(not gw.ingest(r, override=(edge.LOW, cm.NONE))["accepted"] for r in icu_f[:TRIALS]) / TRIALS
    sec["A3_icu_high_with_mask"] = sum(not gw.ingest(r, override=(edge.HIGH, cm.AES_MASK))["accepted"]
                                       for r in icu_f[TRIALS:2 * TRIALS]) / TRIALS
    sec["A3_meter_as_low_ascon"] = sum(not gw.ingest(r, override=(edge.LOW, cm.ASCON))["accepted"] for r in met_f) / len(met_f)
    sec["A3_duplicate_id"] = sum(not gw.ingest(r)["accepted"] for r in rng.sample(recs, TRIALS)) / TRIALS
    rej_gas, unk = [], 0
    for r in rng.sample(fresh[2 * TRIALS * 4:], TRIALS):
        r.dev_id = "rogue-" + r.dev_id
        x = gw.ingest(r)
        unk += not x["accepted"]
        rej_gas.append(x["gas"])
    sec["A3_unknown_device"] = unk / TRIALS
    rc = Contract(dep.chain, dep.c.address, dep.art["AdaptiveTrust"]["hashes"]).tx(
        unreg.acct, "logDecision", os.urandom(32), b32("icu_monitor-00"), 2, 3, os.urandom(32), os.urandom(32))
    sec["A3_non_gateway_reverted"] = 1.0 if int(rc["status"], 16) == 0 else 0.0

    # NEW: non-conformance (gateway declares compliant protection but stores something else)
    wear_f = [r for r in edge.generate(TRIALS * 40, seed=1001) if r.dtype in ("icu_monitor", "wearable_daily")]
    nc = {}
    gas_vote, gas_report = [], []
    for name, kw in (("A3_plaintext_under_AES_claim", dict(store_plaintext=True)),
                     ("A3_header_mismatch", dict(header_override={"cls": 0, "mode": cm.ASCON})),
                     ("A3_wrong_cipher_under_claim", dict(encrypt_as=cm.ASCON)),
                     ("A3_wrong_key_deposited", "WRONGKEY")):
        detected = flagged = denied_after = 0
        for r in [wear_f.pop() for _ in range(TRIALS)]:
            if kw == "WRONGKEY":
                x = gw.ingest(r, deposit_key=os.urandom(32))
            else:
                x = gw.ingest(r, **kw)
            assert x["accepted"]
            st_ = doctor.retrieve(r.data_id)[0]
            detected += st_ == "NONCONFORMANT"
            flagged += dep.record(r.data_id)["status"] == 1
            denied_after += admin.retrieve(r.data_id)[0] == "DENIED"
        nc[name] = {"detected": detected / TRIALS, "flagged": flagged / TRIALS, "denied_after": denied_after / TRIALS}
    sec["nonconformance"] = nc
    out["e5_security"] = sec
    print(json.dumps(sec, indent=1))

    # gas of conformance operations
    r = wear_f.pop()
    gw.ingest(r, store_plaintext=True)
    rc_rep = dep.c.tx(doctor.acct, "reportNonConformance", r.data_id, 2)
    rc_v1 = dep.c.tx(krs.nodes[0].acct, "voteNonConformance", r.data_id, 2)
    rc_v2 = dep.c.tx(krs.nodes[1].acct, "voteNonConformance", r.data_id, 2)

    # ---------------- E3 gas ----------------
    g = lambda rc: int(rc["gasUsed"], 16)  # noqa: E731
    gas = {"deploy_AdaptiveTrust": dep.deploy_gas, **{f"admin_{k}": v for k, v in dep.admin_gas.items()}}
    gas["logDecision_accepted"] = summ([w["gas"] for w in writes])
    gas["logDecision_rejected"] = summ(rej_gas)
    hid = icu[0][0].data_id
    gas["requestAccess_granted"] = g(dep.c.tx(doctor.acct, "requestAccess", hid))
    gas["requestAccess_denied"] = g(dep.c.tx(unreg.acct, "requestAccess", hid))
    gas["reportTamper"] = g(dep.c.tx(doctor.acct, "reportTamper", hid, os.urandom(32)))
    gas["reportNonConformance"] = g(rc_rep)
    gas["voteNonConformance_first"] = g(rc_v1)
    gas["voteNonConformance_flagging"] = g(rc_v2)

    # same-chain baselines
    def deploy(name):
        a, rc_ = dep.chain.deploy(dep.owner, dep.art[name]["bin"])
        return Contract(dep.chain, a, dep.art[name]["hashes"]), g(rc_)
    bare, gas["deploy_BareAnchor"] = deploy("BareAnchor")
    acl, gas["deploy_AnchorACL"] = deploy("AnchorACL")
    naive, gas["deploy_NaiveTrust"] = deploy("NaiveTrust")
    bare.tx(dep.owner, "setWriter", dep.edge_accounts[0], True)
    acl.tx(dep.owner, "setWriter", dep.edge_accounts[0], True)
    acl.tx(dep.owner, "registerUser", doctor.acct, 1)
    acl.tx(dep.owner, "setRoleCanRead", 1, b32("icu_monitor"), True)
    for c_, m_ in (("High", "AES"), ("Medium", "AES+Mask"), ("Low", "Lightweight")):
        naive.tx(dep.owner, "setPolicy", c_, m_)
    gb, ga, gacc, gn = [], [], [], []
    cls_name = {0: "Low", 1: "Medium", 2: "High"}
    mode_name = {0: "Lightweight", 1: "Lightweight", 2: "AES+Mask", 3: "AES", 4: "AES"}
    for (r, w) in pool[:300]:
        did = sha256(r.data_id, b"baseline")
        gb.append(g(bare.tx(dep.edge_accounts[0], "anchor", did, os.urandom(32), os.urandom(32))))
        ga.append(g(acl.tx(dep.edge_accounts[0], "anchor", did, b32(r.dtype), os.urandom(32), os.urandom(32))))
        a1 = naive.tx(dep.owner, "validateDecision", did, cls_name[w["C"]], mode_name[w["E"]])
        a2 = naive.tx(dep.owner, "logHash", did, os.urandom(32), "ipfs:bafkreigh2akiscaildcqabsyg3dfr6chu3fgpregiymsck7e7aqa4s52zy")
        gn.append(g(a1) + g(a2))
        if r.dtype == "icu_monitor":
            gacc.append(g(acl.tx(doctor.acct, "requestAccess", did)))
    gas["baseline_bare_anchor"] = summ(gb)
    gas["baseline_acl_anchor"] = summ(ga)
    gas["baseline_acl_requestAccess"] = summ(gacc)
    gas["baseline_naive_two_tx"] = summ(gn)
    out["e3_gas"] = gas
    print({k: (v if isinstance(v, int) else round(v["mean"])) for k, v in gas.items()})
    with open(os.path.join(OUT, "e3_e5_v2.json"), "w") as f:
        json.dump(out, f, indent=1)


if __name__ == "__main__":
    main()
