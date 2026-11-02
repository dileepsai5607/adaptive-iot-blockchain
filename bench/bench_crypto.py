"""E1: cryptographic cost per protection mode vs payload size, Paillier
micro-costs, and storage-backend latency (SQLite vs IPFS)."""
import json
import os
import statistics as st
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))
import crypto_modes as cm  # noqa: E402

OUT = os.path.join(os.path.dirname(__file__), "..", "results")
os.makedirs(OUT, exist_ok=True)
SIZES = [64, 256, 1024, 4096, 16384, 65536]
REPS = {64: 2000, 256: 2000, 1024: 2000, 4096: 1000, 16384: 500, 65536: 200}


def timeit(fn, reps):
    xs = []
    for _ in range(reps):
        t0 = time.perf_counter()
        fn()
        xs.append((time.perf_counter() - t0) * 1e6)  # microseconds
    xs.sort()
    return {"median_us": st.median(xs), "mean_us": st.mean(xs), "p95_us": xs[int(0.95 * len(xs)) - 1],
            "std_us": st.pstdev(xs)}


def main():
    pub, priv = cm.paillier_keygen(2048)
    mask_key = os.urandom(32)
    aad = b'{"cls":2,"dtype":"x","id":"00","mode":3,"ts":1}'
    results = {"modes": [], "paillier": {}, "storage": []}

    for size in SIZES:
        pt = os.urandom(size)
        reps = REPS[size]
        k16, n16 = os.urandom(16), os.urandom(16)
        k32, n12 = os.urandom(32), os.urandom(12)
        c_ascon = cm.ascon_encrypt(k16, n16, aad, pt)
        c_aes = cm.aes_encrypt(k32, n12, aad, pt)
        ids = ["PT-50001", "WARD-7"]

        def mask_enc():
            [cm.mask_token(mask_key, i) for i in ids]
            return cm.aes_encrypt(k32, n12, aad, pt)

        phe_vals = [7312, 8125, 650]   # steps, avg_hr*100, sleep*100 (3 numeric fields)

        def phe_enc():
            [pub.encrypt(v) for v in phe_vals]
            return cm.aes_encrypt(k32, n12, aad, pt)
        phe_cts = [pub.encrypt(v) for v in phe_vals]

        def phe_dec():
            [priv.decrypt(c) for c in phe_cts]
            return cm.aes_decrypt(k32, n12, aad, c_aes)

        phe_reps = max(50, reps // 20)
        rows = [
            ("None", lambda: bytes(pt), lambda: bytes(pt), size, reps),
            ("ASCON-128", lambda: cm.ascon_encrypt(k16, n16, aad, pt), lambda: cm.ascon_decrypt(k16, n16, aad, c_ascon),
             len(c_ascon), reps),
            ("AES+Mask", mask_enc, lambda: cm.aes_decrypt(k32, n12, aad, c_aes), len(c_aes) + 2 * 32, reps),
            ("AES-GCM", lambda: cm.aes_encrypt(k32, n12, aad, pt), lambda: cm.aes_decrypt(k32, n12, aad, c_aes),
             len(c_aes), reps),
            ("AES+PHE", phe_enc, phe_dec, len(c_aes) + 3 * 512, phe_reps),
        ]
        for name, enc, dec, ctlen, r in rows:
            e, d = timeit(enc, r), timeit(dec, r)
            results["modes"].append({"mode": name, "size": size, "enc": e, "dec": d, "ct_bytes": ctlen,
                                     "overhead_bytes": ctlen - size, "reps": r})
            print(f"{name:10s} {size:6d}B enc {e['median_us']:9.1f}us dec {d['median_us']:9.1f}us")

    # Paillier micro-costs
    t0 = time.perf_counter()
    for _ in range(5):
        cm.paillier_keygen(2048)
    kg = (time.perf_counter() - t0) / 5 * 1000
    c1, c2 = pub.encrypt(100), pub.encrypt(200)
    res = {
        "keygen_ms": kg,
        "encrypt": timeit(lambda: pub.encrypt(12345), 300),
        "decrypt_crt": timeit(lambda: priv.decrypt(c1), 300),
        "hom_add": timeit(lambda: pub.add(c1, c2), 3000),
        "ciphertext_bytes": (pub.n2.bit_length() + 7) // 8,
    }
    agg = []
    for n in (100, 1000, 10000):
        cts = [pub.encrypt(v) for v in range(min(n, 1000))]
        cts = (cts * (n // len(cts) + 1))[:n]
        t0 = time.perf_counter()
        acc = cts[0]
        for c in cts[1:]:
            acc = pub.add(acc, c)
        dt = (time.perf_counter() - t0) * 1000
        t1 = time.perf_counter()
        priv.decrypt(acc)
        agg.append({"n": n, "aggregate_ms": dt, "decrypt_ms": (time.perf_counter() - t1) * 1000})
    res["aggregation"] = agg
    results["paillier"] = res
    print("Paillier", json.dumps({k: v for k, v in res.items() if k != "aggregation"}, default=str)[:300])
    print("aggregation", agg)

    with open(os.path.join(OUT, os.environ.get("E1_OUT", "e1_crypto.json")), "w") as f:
        json.dump(results, f, indent=1)


if __name__ == "__main__":
    main()
