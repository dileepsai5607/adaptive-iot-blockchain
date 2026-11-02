"""E1c: key-management operations - classical vs hybrid (X25519+ML-KEM-768) key wrap,
Shamir 2-of-3 split/combine of a data key, threshold Paillier partial/combine."""
import json
import os
import statistics as st
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))
import crypto_modes as cm  # noqa: E402
import threshold as th  # noqa: E402

OUT = os.path.join(os.path.dirname(__file__), "..", "results")


def med(fn, reps):
    xs = []
    for _ in range(reps):
        t0 = time.perf_counter()
        fn()
        xs.append((time.perf_counter() - t0) * 1e3)
    return st.median(xs)


def run():
    u = cm.UserKeys()
    sk, pk = cm.x25519_keypair()
    dek, ctx = os.urandom(32), b"x" * 33
    hb, cb = cm.wrap_key(u.pub, dek, ctx), cm.wrap_key(pk, dek, ctx)
    shares = th.shamir_split(dek, 3, 2)
    pub, priv = cm.paillier_keygen(2048)
    tp = th.ThresholdPaillier(pub, priv.p, priv.q, 3, 2)
    c = pub.encrypt(12345)
    parts = {1: tp.partial(1, c), 2: tp.partial(2, c)}
    return {
        "wrap_classic_ms": med(lambda: cm.wrap_key(pk, dek, ctx), 500),
        "unwrap_classic_ms": med(lambda: cm.unwrap_key(sk, cb, ctx), 500),
        "wrap_hybrid_ms": med(lambda: cm.wrap_key(u.pub, dek, ctx), 500),
        "unwrap_hybrid_ms": med(lambda: cm.unwrap_key(u, hb, ctx), 500),
        "wrap_classic_bytes": len(cb), "wrap_hybrid_bytes": len(hb),
        "shamir_split_ms": med(lambda: th.shamir_split(dek, 3, 2), 2000),
        "shamir_combine_ms": med(lambda: th.shamir_combine(shares[:2]), 2000),
        "tpaillier_partial_ms": med(lambda: tp.partial(1, c), 100),
        "tpaillier_combine_ms": med(lambda: tp.combine(parts), 200),
        "paillier_crt_decrypt_ms": med(lambda: priv.decrypt(c), 200),
    }


if __name__ == "__main__":
    runs = [run() for _ in range(5)]
    out = {k: {"mean": st.mean(r[k] for r in runs), "sd": st.pstdev(r[k] for r in runs)} for k in runs[0]}
    json.dump({"runs": runs, "summary": out}, open(os.path.join(OUT, "e1c_keyops.json"), "w"), indent=1)
    for k, v in out.items():
        print(f"{k:26s} {v['mean']:10.4f} ± {v['sd']:.4f}")
