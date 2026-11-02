"""E8: adaptation under load. A single-worker gateway (one core; real-time records served first,
non-preemptive) receives steady real-time telemetry plus a burst of wearable daily summaries
(e.g. a nightly sync). Static policy: wearables always AES+PHE. Adaptive: the resource score uses
the gateway's own CPU headroom (busy fraction over the last second), so PHE yields to AES-GCM
when the gateway saturates and resumes when headroom returns. Anchoring is asynchronous and off
the critical path, so it is not part of this experiment."""
import heapq
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
from framework import Gateway, UtilizationMonitor, sha256  # noqa: E402
from storage import SQLStore  # noqa: E402

OUT = os.path.join(os.path.dirname(__file__), "..", "results")
DUR = float(os.environ.get("DUR", 60))
BURST = tuple(float(x) for x in os.environ.get("BURST", "20,40").split(","))
RT_RATE = float(os.environ.get("RT_RATE", 150))     # records/s of real-time + other telemetry
WEAR_RATE = float(os.environ.get("WEAR_RATE", 80))  # wearable summaries/s during the burst
RT_TYPES = {"icu_monitor": .3, "industrial_plc": .3, "traffic_counter": .2, "env_sensor": .1, "smart_meter": .1}


class NullKRS:
    def deposit(self, *a):
        pass


def schedule(seed):
    rng = random.Random(seed)
    pool_rt = edge.generate(int(DUR * RT_RATE * 2), seed=seed, mix=RT_TYPES)
    pool_w = edge.generate(int((BURST[1] - BURST[0]) * WEAR_RATE * 1.5) + 200, seed=seed + 1,
                           mix={"wearable_daily": 1.0})
    ev, t, i = [], 0.0, 0
    while True:
        t += rng.expovariate(RT_RATE)
        if t >= DUR:
            break
        ev.append((t, pool_rt[i])); i += 1
    t, j = BURST[0], 0
    while True:
        t += rng.expovariate(WEAR_RATE)
        if t >= BURST[1]:
            break
        ev.append((t, pool_w[j])); j += 1
    # a trickle of wearables outside the burst
    t = 0.0
    while True:
        t += rng.expovariate(2.0)
        if t >= DUR:
            break
        if not BURST[0] <= t < BURST[1]:
            ev.append((t, pool_w[j])); j += 1
    ev.sort(key=lambda e: e[0])
    return ev


def run(policy, seed, phe_pub):
    sql = SQLStore(":memory:")
    mon = UtilizationMonitor(window=1.0)
    gw = Gateway(None, None, NullKRS(), phe_pub, sql, None,
                 load_fn=(lambda: (mon.headroom(), 0.9, 1.0)) if policy == "adaptive" else (lambda: (1.0, 0.9, 1.0)))
    ev = schedule(seed)
    q, lock, cv = [], threading.Lock(), threading.Condition()
    done = []
    finished = [False]
    t0 = time.perf_counter() + 0.5

    def producer():
        for k, (ta, r) in enumerate(ev):
            d = t0 + ta - time.perf_counter()
            if d > 0:
                time.sleep(d)
            with cv:
                heapq.heappush(q, (0 if r.rt else 1, ta, k, r))
                cv.notify()
        with cv:
            finished[0] = True
            cv.notify()

    def worker():
        while True:
            with cv:
                while not q and not finished[0]:
                    cv.wait()
                if not q:
                    return
                _, ta, k, r = heapq.heappop(q)
            s = time.perf_counter()
            S, R, C, E = gw.analyse(r)
            env, dek = gw.protect(r, C, E)
            ref = gw.store(env)
            sha256(env, ref.encode())
            e = time.perf_counter()
            mon.add(s, e)
            done.append({"t": ta, "lat_ms": (e - (t0 + ta)) * 1e3, "rt": r.rt, "dtype": r.dtype, "E": E,
                         "budget": r.budget_ms, "svc_ms": (e - s) * 1e3, "R": R})

    th_p, th_w = threading.Thread(target=producer), threading.Thread(target=worker)
    th_p.start(); th_w.start(); th_p.join(); th_w.join()
    sql.db.close()
    return done


def summarize(done):
    rt = [d for d in done if d["rt"]]
    wear = [d for d in done if d["dtype"] == "wearable_daily"]
    wb = [d for d in wear if BURST[0] <= d["t"] < BURST[1]]
    rtb = [d for d in rt if BURST[0] <= d["t"] < BURST[1] + 10]
    miss = lambda xs: sum(d["lat_ms"] > d["budget"] for d in xs) / max(1, len(xs))  # noqa: E731
    p = lambda xs, q: sorted(xs)[max(0, int(q * len(xs)) - 1)] if xs else 0  # noqa: E731
    plc = [d for d in rtb if d["dtype"] == "industrial_plc"]
    return {
        "n": len(done),
        "rt_miss_all": miss(rt), "rt_miss_burst": miss(rtb), "plc_miss_burst": miss(plc),
        "rt_p95_burst_ms": p([d["lat_ms"] for d in rtb], .95), "rt_p99_burst_ms": p([d["lat_ms"] for d in rtb], .99),
        "wear_phe_share_burst": sum(d["E"] == cm.AES_PHE for d in wb) / max(1, len(wb)),
        "wear_phe_share_all": sum(d["E"] == cm.AES_PHE for d in wear) / max(1, len(wear)),
        "wear_max_lat_ms": max(d["lat_ms"] for d in wear), "wear_miss": miss(wear),
    }


def series(done, step=1.0):
    out = []
    for b in range(int(DUR / step)):
        lo, hi = b * step, (b + 1) * step
        w = [d for d in done if lo <= d["t"] < hi]
        rt = [d for d in w if d["rt"]]
        wear = [d for d in w if d["dtype"] == "wearable_daily"]
        out.append({"t": lo, "rt_p95": sorted(d["lat_ms"] for d in rt)[max(0, int(.95 * len(rt)) - 1)] if rt else None,
                    "rt_miss": sum(d["lat_ms"] > d["budget"] for d in rt) / len(rt) if rt else None,
                    "phe_share": sum(d["E"] == cm.AES_PHE for d in wear) / len(wear) if wear else None,
                    "wear_n": len(wear), "util": sum(d["svc_ms"] for d in w) / (step * 1e3),
                    "wear_lat_med": sorted(d["lat_ms"] for d in wear)[len(wear) // 2] if wear else None,
                    "wear_lat_max": max(d["lat_ms"] for d in wear) if wear else None})
    return out


if __name__ == "__main__":
    phe_pub, _ = cm.paillier_keygen(2048)
    reps = int(os.environ.get("REPS", 3))
    res = {"config": {"DUR": DUR, "BURST": BURST, "RT_RATE": RT_RATE, "WEAR_RATE": WEAR_RATE, "R_MIN": edge.R_MIN},
           "runs": []}
    for k in range(reps):
        for pol in ("static", "adaptive"):
            d = run(pol, 100 + k, phe_pub)
            s = summarize(d)
            res["runs"].append({"policy": pol, "rep": k, "summary": s, "series": series(d)})
            print(pol, k, {a: round(b, 4) if isinstance(b, float) else b for a, b in s.items()}, flush=True)
    json.dump(res, open(os.path.join(OUT, os.environ.get("E8_OUT", "e8_dynamic.json")), "w"), indent=1)
