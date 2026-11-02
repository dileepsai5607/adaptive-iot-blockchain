"""Edge analysis (sensitivity S, resource score R, latency budget L) and the
decision engine (Algorithm 1). Resource and latency only choose among the modes
the policy already permits for a class; they never lower the class."""
import hashlib
import os
import random
import struct
import time
from dataclasses import dataclass, field

from crypto_modes import NONE, ASCON, AES_MASK, AES, AES_PHE

LOW, MEDIUM, HIGH = 0, 1, 2
CLASS_NAMES = {LOW: "Low", MEDIUM: "Medium", HIGH: "High"}

# Weights for S (Eq. 3) and R (Eq. 4)
W_TYPE, W_CTX, W_DOMAIN, W_REG = 0.4, 0.2, 0.2, 0.2
# R (Eq. 2): gateway CPU headroom c, memory headroom m, power state b (1 = mains), uplink quality n.
A_CPU, B_MEM, G_BAT, D_NET = 0.5, 0.1, 0.2, 0.2
T_HIGH, T_MED = 80, 40
R_MIN = 0.6          # minimum resource score for Paillier (falls below at ~2/3 gateway utilization)
L_PHE_MS = 500       # PHE only if the latency budget is at least this
DOMAIN_SCORE = {"health": 100, "industrial": 80, "surveillance": 70, "energy": 60, "city": 20}

# Device-type profiles: base type score, domain, regulated?, real-time, budget, fields
PROFILES = {
    "env_sensor":     dict(s_type=10, domain="city", reg=0, rt=0, budget=5000, public=True, battery=True,
                           ids=[], phe=[]),
    "traffic_counter": dict(s_type=15, domain="city", reg=0, rt=1, budget=50, public=False, battery=False,
                            ids=["intersection"], phe=[]),
    "smart_meter":    dict(s_type=60, domain="energy", reg=100, rt=0, budget=2000, public=False, battery=False,
                           ids=["household_id"], phe=[]),
    "industrial_plc": dict(s_type=80, domain="industrial", reg=60, rt=1, budget=20, public=False, battery=False,
                           ids=["machine_id"], phe=[]),
    "icu_monitor":    dict(s_type=100, domain="health", reg=100, rt=1, budget=50, public=False, battery=False,
                           ids=["patient_id"], phe=[]),
    "wearable_daily": dict(s_type=90, domain="health", reg=100, rt=0, budget=10000, public=False, battery=True,
                           ids=["patient_id"], phe=["steps", "avg_hr", "sleep_h"]),
    "cctv_frame":     dict(s_type=90, domain="surveillance", reg=100, rt=1, budget=100, public=False, battery=False,
                           ids=["camera_id", "location"], phe=[]),
}
# On-chain floors (minimum class per data type)
MIN_CLASS = {"env_sensor": LOW, "traffic_counter": LOW, "smart_meter": MEDIUM, "industrial_plc": MEDIUM,
             "icu_monitor": HIGH, "wearable_daily": HIGH, "cctv_frame": HIGH}
# On-chain allowed-mode bitmasks per class
ALLOWED = {LOW: 0b11111, MEDIUM: 0b11100, HIGH: 0b11000}


def context_score(dtype: str, p: dict) -> int:
    """Context raises sensitivity for abnormal / critical readings."""
    if dtype == "env_sensor":
        return 30 if p["pm25"] > 150 else 0
    if dtype == "traffic_counter":
        return 0
    if dtype == "smart_meter":
        return 50 if p["kwh"] > 4.0 else 20
    if dtype == "industrial_plc":
        return 100 if p["alarm"] else 40
    if dtype == "icu_monitor":
        return 100 if (p["spo2"] < 90 or p["hr"] > 130 or p["hr"] < 45) else 70
    if dtype == "wearable_daily":
        return 50
    if dtype == "cctv_frame":
        return 100 if p["motion"] else 50
    return 0


def sensitivity(dtype: str, payload: dict) -> float:
    prof = PROFILES[dtype]
    return (W_TYPE * prof["s_type"] + W_CTX * context_score(dtype, payload)
            + W_DOMAIN * DOMAIN_SCORE[prof["domain"]] + W_REG * prof["reg"])


def gateway_load():
    """CPU and memory availability of the edge gateway itself, in [0,1]."""
    try:
        load1 = os.getloadavg()[0] / (os.cpu_count() or 1)
        c = max(0.0, 1.0 - load1)
        with open("/proc/meminfo") as f:
            mi = {l.split(":")[0]: int(l.split()[1]) for l in f}
        m = mi["MemAvailable"] / mi["MemTotal"]
    except Exception:
        c, m = 1.0, 1.0
    return c, m


def resource_score(c, m, b, n) -> float:
    return A_CPU * c + B_MEM * m + G_BAT * b + D_NET * n


def classify(S: float) -> int:
    if S >= T_HIGH:
        return HIGH
    if S >= T_MED:
        return MEDIUM
    return LOW


def decide(dtype: str, S: float, R: float, L: float, rt: int, open_data_policy=True):
    """Algorithm 1. Returns (class, mode). The class is clamped to the on-chain floor of the
    device's data type, so a mis-tuned score can escalate protection but never lower it."""
    C = max(classify(S), MIN_CLASS[dtype])
    prof = PROFILES[dtype]
    if C == HIGH:
        if rt == 1 or R < R_MIN or L < L_PHE_MS or not prof["phe"]:
            E = AES
        else:
            E = AES_PHE
    elif C == MEDIUM:
        E = AES_MASK if prof["ids"] else AES
    else:
        E = NONE if (prof["public"] and open_data_policy) else ASCON
    return C, E


# --------------------------- workload generator ---------------------------
@dataclass
class Record:
    data_id: bytes
    dev_id: str
    dtype: str
    ts: float
    rt: int
    payload: dict
    blob: bytes = b""
    battery: float = 1.0
    net: float = 1.0
    budget_ms: float = 1000.0


def make_payload(dtype, rng: random.Random, dev_idx: int):
    if dtype == "env_sensor":
        return {"temp_c": round(rng.uniform(18, 42), 2), "humidity": round(rng.uniform(20, 95), 1),
                "pm25": round(rng.choice([rng.uniform(5, 120)] * 9 + [rng.uniform(150, 300)]), 1)}, b""
    if dtype == "traffic_counter":
        return {"intersection": f"JN-{dev_idx:03d}", "vehicles": rng.randint(0, 80),
                "avg_speed": round(rng.uniform(5, 60), 1)}, b""
    if dtype == "smart_meter":
        return {"household_id": f"HH-{10000 + dev_idx}", "kwh": round(rng.choice([rng.uniform(0.1, 3.5)] * 8 + [rng.uniform(4, 9)] * 2), 3),
                "voltage": round(rng.uniform(220, 245), 1)}, b""
    if dtype == "industrial_plc":
        alarm = rng.random() < 0.15
        return {"machine_id": f"MC-{dev_idx:04d}", "vibration_mm_s": round(rng.uniform(1, 18 if alarm else 7), 2),
                "temp_c": round(rng.uniform(40, 110 if alarm else 80), 1), "alarm": alarm}, b""
    if dtype == "icu_monitor":
        crit = rng.random() < 0.1
        return {"patient_id": f"PT-{50000 + dev_idx}", "hr": rng.randint(135, 170) if crit else rng.randint(55, 110),
                "spo2": rng.randint(82, 89) if crit else rng.randint(93, 100),
                "sys": rng.randint(95, 150), "dia": rng.randint(60, 95)}, b""
    if dtype == "wearable_daily":
        return {"patient_id": f"PT-{60000 + dev_idx}", "steps": rng.randint(800, 16000),
                "avg_hr": round(rng.uniform(58, 95), 1), "sleep_h": round(rng.uniform(4, 9.5), 2)}, b""
    if dtype == "cctv_frame":
        size = rng.choice([16, 32, 64]) * 1024
        return {"camera_id": f"CAM-{dev_idx:03d}", "location": f"Gate-{dev_idx % 7}",
                "motion": rng.random() < 0.3, "frame_bytes": size}, rng.randbytes(size)
    raise ValueError(dtype)


# Mixed smart-campus / hospital / factory workload mix
DEFAULT_MIX = {"env_sensor": 0.25, "traffic_counter": 0.15, "smart_meter": 0.15, "industrial_plc": 0.15,
               "icu_monitor": 0.12, "wearable_daily": 0.10, "cctv_frame": 0.08}


def generate(n: int, seed=7, mix=None, devices_per_type=10):
    rng = random.Random(seed)
    mix = mix or DEFAULT_MIX
    types, weights = zip(*mix.items())
    out = []
    t0 = 1_760_000_000.0
    for i in range(n):
        dtype = rng.choices(types, weights)[0]
        idx = rng.randrange(devices_per_type)
        prof = PROFILES[dtype]
        payload, blob = make_payload(dtype, rng, idx)
        dev_id = f"{dtype}-{idx:02d}"
        ts = t0 + i * 0.05
        data_id = hashlib.sha256(f"{dev_id}|{i}|{ts}".encode()).digest()
        out.append(Record(data_id, dev_id, dtype, ts, prof["rt"], payload, blob,
                          battery=rng.uniform(0.1, 1.0) if prof["battery"] else 1.0,
                          net=rng.uniform(0.3, 1.0), budget_ms=prof["budget"]))
    return out
