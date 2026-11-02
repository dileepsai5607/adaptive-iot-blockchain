"""E1b: AES-GCM without AES-NI/PCLMUL (software AES, as on gateways without AES
hardware) vs ASCON. Run with OPENSSL_ia32cap set to mask the CPU features."""
import json, os, sys, time, statistics as st
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))
import crypto_modes as cm
OUT = os.path.join(os.path.dirname(__file__), "..", "results")
res = []
aad = b"0" * 48
for size in [64, 256, 1024, 4096, 16384, 65536]:
    pt = os.urandom(size); k32, n12 = os.urandom(32), os.urandom(12); k16, n16 = os.urandom(16), os.urandom(16)
    reps = 2000 if size <= 4096 else 300
    def t(fn):
        xs = []
        for _ in range(reps):
            a = time.perf_counter(); fn(); xs.append((time.perf_counter() - a) * 1e6)
        return st.median(xs)
    a = t(lambda: cm.aes_encrypt(k32, n12, aad, pt)); s = t(lambda: cm.ascon_encrypt(k16, n16, aad, pt))
    res.append({"size": size, "aes_gcm_sw_us": a, "ascon_us": s})
    print(size, "AES-GCM(sw)", round(a, 1), "ASCON", round(s, 1))
json.dump({"ia32cap": os.environ.get("OPENSSL_ia32cap"), "rows": res}, open(os.path.join(OUT, os.environ.get("E1B_OUT", "e1b_noaesni.json")), "w"), indent=1)
