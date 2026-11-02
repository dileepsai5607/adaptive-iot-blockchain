"""Generate paper figures (PDF, IEEE single-column width) from results/*.json."""
import json
import os

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402

R = os.path.join(os.path.dirname(__file__), "..", "results")
F = os.path.join(os.path.dirname(__file__), "..", "figures")
os.makedirs(F, exist_ok=True)

# Validated categorical palette (fixed order) + distinct markers/dashes for print & CVD
C = ["#2a78d6", "#eb6834", "#1baf7a", "#eda100", "#e87ba4", "#008300"]
MK = ["o", "s", "^", "D", "v", "P"]
LS = ["-", "--", "-.", ":", (0, (5, 1, 1, 1)), (0, (3, 1))]
INK, INK2, GRID = "#0b0b0b", "#52514e", "#e4e3df"

plt.rcParams.update({
    "font.family": "serif", "font.size": 8, "axes.titlesize": 8, "axes.labelsize": 8,
    "xtick.labelsize": 7, "ytick.labelsize": 7, "legend.fontsize": 6.5,
    "axes.edgecolor": INK2, "axes.labelcolor": INK, "xtick.color": INK2, "ytick.color": INK2,
    "axes.grid": True, "grid.color": GRID, "grid.linewidth": 0.5, "axes.spines.top": False,
    "axes.spines.right": False, "lines.linewidth": 1.4, "lines.markersize": 4, "pdf.fonttype": 42,
})
W = 3.45  # IEEE column width in inches


def sizelabel(s):
    return f"{s // 1024}K" if s >= 1024 else str(s)


def fig_crypto():
    d = json.load(open(os.path.join(R, "e1_crypto.json")))
    b = json.load(open(os.path.join(R, "e1b_noaesni.json")))
    modes = ["None", "ASCON-128", "AES+Mask", "AES-GCM", "AES+PHE"]
    fig, axs = plt.subplots(1, 2, figsize=(W * 2, 2.1))
    ax = axs[0]
    for i, m in enumerate(modes):
        rows = [r for r in d["modes"] if r["mode"] == m]
        xs = [r["size"] for r in rows]
        ys = [r["enc"]["median_us"] for r in rows]
        ax.plot(xs, ys, color=C[i], marker=MK[i], linestyle=LS[i], label=m)
    ax.set_xscale("log", base=2)
    ax.set_yscale("log")
    ax.set_xticks([r["size"] for r in d["modes"] if r["mode"] == "None"])
    ax.set_xticklabels([sizelabel(r["size"]) for r in d["modes"] if r["mode"] == "None"])
    ax.set_xlabel("Payload size (bytes)")
    ax.set_ylabel("Encryption time (µs, median)")
    ax.set_title("(a) Protection cost per mode (x86 edge, AES-NI)")
    ax.legend(ncol=3, frameon=False, loc="upper left", bbox_to_anchor=(0.0, 0.86), fontsize=6.2)
    ax.grid(True, which="minor", linewidth=0.3, color=GRID)

    ax = axs[1]
    xs = [r["size"] for r in b["rows"]]
    hw = {r["size"]: r["enc"]["median_us"] for r in d["modes"] if r["mode"] == "AES-GCM"}
    ax.plot(xs, [hw[x] for x in xs], color=C[3], marker=MK[3], linestyle=LS[3], label="AES-GCM (AES-NI)")
    ax.plot(xs, [r["aes_gcm_sw_us"] for r in b["rows"]], color=C[0], marker=MK[0], linestyle=LS[0],
            label="AES-GCM (software)")
    ax.plot(xs, [r["ascon_us"] for r in b["rows"]], color=C[1], marker=MK[1], linestyle=LS[1], label="ASCON-AEAD128")
    ax.set_xscale("log", base=2)
    ax.set_yscale("log")
    ax.set_xticks(xs)
    ax.set_xticklabels([sizelabel(x) for x in xs])
    ax.set_xlabel("Payload size (bytes)")
    ax.set_ylabel("Encryption time (µs, median)")
    ax.set_title("(b) ASCON vs AES-GCM, with/without AES-NI")
    ax.legend(frameon=False, loc="upper left")
    fig.tight_layout()
    fig.savefig(os.path.join(F, "fig_crypto.pdf"))
    fig.savefig(os.path.join(F, "fig_crypto.png"), dpi=200)


def fig_stages():
    d = json.load(open(os.path.join(R, "e2_e3_e5.json")))
    modes = ["None", "ASCON-128", "AES+Mask", "AES-GCM", "AES+PHE"]
    fig, axs = plt.subplots(1, 2, figsize=(W * 2, 2.35), sharey=True)
    panels = [
        ("e2_write", ["edge_analysis", "encrypt", "store", "hash", "chain_anchor"],
         ["Edge analysis", "Encrypt", "Store", "Hash", "Chain anchor"], "(a) Write path"),
        ("e2_read", ["access_request", "chain_read", "fetch", "verify", "decrypt"],
         ["Access tx", "Chain read", "Fetch", "Verify", "Key release + decrypt"], "(b) Read path"),
    ]
    for ax, (key, stages, labels, title) in zip(axs, panels):
        left = [0.0] * len(modes)
        for i, (s, lab) in enumerate(zip(stages, labels)):
            vals = [d[key][m][s]["median"] for m in modes]
            ax.barh(modes, vals, left=left, color=C[i], edgecolor="white", linewidth=0.8, height=0.6, label=lab)
            left = [a + v for a, v in zip(left, vals)]
        for y, tot in enumerate(left):
            ax.text(tot + 0.4, y, f"{tot:.1f}", va="center", fontsize=6.5, color=INK)
        ax.set_xlabel("Latency (ms); bar = sum of stage medians")
        ax.set_title(title, pad=16)
        ax.legend(frameon=False, fontsize=5.8, loc="lower center", bbox_to_anchor=(0.5, 1.0), ncol=5,
                  handlelength=1.0, columnspacing=0.8, borderaxespad=0.1)
        ax.grid(axis="y", visible=False)
        ax.set_xlim(0, max(left) * 1.15)
    axs[0].invert_yaxis()
    fig.tight_layout()
    fig.savefig(os.path.join(F, "fig_stages.pdf"))
    fig.savefig(os.path.join(F, "fig_stages.png"), dpi=200)


def fig_storage_throughput():
    d = json.load(open(os.path.join(R, "e2_e3_e5.json")))
    t = json.load(open(os.path.join(R, "e2_e4_reth.json")))
    g = json.load(open(os.path.join(R, "e2_e3_e5.json")))["e3_gas"]["logDecision_accepted"]["mean"]
    fig, axs = plt.subplots(1, 2, figsize=(W * 2, 2.0))
    ax = axs[0]
    k = 0
    for be, name in (("sqlite", "SQLite"), ("ipfs", "IPFS")):
        rows = [r for r in d["storage"] if r["backend"] == be]
        xs = [r["size"] for r in rows]
        for op in ("put", "get"):
            ax.plot(xs, [r[op]["median"] for r in rows], color=C[k], marker=MK[k], linestyle=LS[k],
                    label=f"{name} {'store' if op == 'put' else 'fetch'}")
            k += 1
    ax.set_xscale("log", base=2)
    ax.set_yscale("log")
    ax.set_xticks(xs)
    ax.set_xticklabels([sizelabel(x) for x in xs])
    ax.set_xlabel("Object size (bytes)")
    ax.set_ylabel("Latency (ms, median)")
    ax.set_title("(a) Off-chain storage latency")
    ax.legend(frameon=False, ncol=2, loc="upper left", fontsize=6)
    ax.set_ylim(top=30)

    ax = axs[1]
    for i, mode in enumerate(("sync", "async")):
        rows = [r for r in t["e4_throughput"] if r["mode"] == mode]
        ax.plot([r["gateways"] for r in rows], [r["tps"] for r in rows], color=C[i], marker=MK[i], linestyle=LS[i],
                label="Synchronous anchoring" if mode == "sync" else "Asynchronous anchoring")
        for r in rows:
            if r["gateways"] in (1, 8):
                ax.annotate(f"{r['tps']:.0f}" if r["tps"] >= 10 else f"{r['tps']:.1f}", (r["gateways"], r["tps"]),
                            textcoords="offset points", xytext=(0, -11 if mode == "async" else 5), ha="center",
                            fontsize=6.5, color=INK)
    cap = t["block_stats"]["gas_limit"] / g
    ax.axhline(cap, color=INK2, linewidth=0.8, linestyle=(0, (2, 2)))
    ax.text(1.0, cap * 1.45, f"chain capacity: {t['block_stats']['gas_limit'] / 1e6:.0f}M gas / {g / 1e3:.0f}k gas per record = {cap:.0f}/s",
            fontsize=6, color=INK2)
    ax.set_xscale("log", base=2)
    ax.set_yscale("log")
    ax.set_ylim(0.5, 1000)
    ax.set_xticks([1, 2, 4, 8])
    ax.set_xticklabels(["1", "2", "4", "8"])
    ax.set_xlabel("Concurrent edge gateways")
    ax.set_ylabel("Records anchored per second")
    ax.set_title("(b) Write throughput, Reth, 1 s blocks")
    ax.legend(frameon=False, loc="center left", bbox_to_anchor=(0.0, 0.5))
    fig.tight_layout()
    fig.savefig(os.path.join(F, "fig_storage_tp.pdf"))
    fig.savefig(os.path.join(F, "fig_storage_tp.png"), dpi=200)


if __name__ == "__main__":
    fig_crypto()
    fig_storage_throughput()
    print("figures written")


def fig_throughput_single():
    """Single-column throughput figure used in the paper."""
    t = json.load(open(os.path.join(R, "e2_e4_reth.json")))
    g = json.load(open(os.path.join(R, "e2_e3_e5.json")))["e3_gas"]["logDecision_accepted"]["mean"]
    fig, ax = plt.subplots(figsize=(W, 2.0))
    for i, mode in enumerate(("sync", "async")):
        rows = [r for r in t["e4_throughput"] if r["mode"] == mode]
        ax.plot([r["gateways"] for r in rows], [r["tps"] for r in rows], color=C[i], marker=MK[i], linestyle=LS[i],
                label="Synchronous anchoring" if mode == "sync" else "Asynchronous anchoring")
        for r in rows:
            if r["gateways"] in (1, 8):
                ax.annotate(f"{r['tps']:.0f}" if r["tps"] >= 10 else f"{r['tps']:.1f}", (r["gateways"], r["tps"]),
                            textcoords="offset points", xytext=(0, -11 if mode == "async" else 5), ha="center",
                            fontsize=6.5, color=INK)
    cap = t["block_stats"]["gas_limit"] / g
    ax.axhline(cap, color=INK2, linewidth=0.8, linestyle=(0, (2, 2)))
    ax.text(1.0, cap * 1.45, f"chain capacity {cap:.0f}/s (36M gas / 131k gas)", fontsize=6, color=INK2)
    ax.set_xscale("log", base=2)
    ax.set_yscale("log")
    ax.set_ylim(0.5, 1000)
    ax.set_xticks([1, 2, 4, 8])
    ax.set_xticklabels(["1", "2", "4", "8"])
    ax.set_xlabel("Concurrent edge gateways")
    ax.set_ylabel("Records anchored / s")
    ax.legend(frameon=False, loc="center left", bbox_to_anchor=(0.0, 0.5))
    fig.tight_layout()
    fig.savefig(os.path.join(F, "fig_throughput.pdf"))
    fig.savefig(os.path.join(F, "fig_throughput.png"), dpi=200)


fig_throughput_single()
