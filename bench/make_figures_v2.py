"""Figures for the revised paper (means over repetitions)."""
import json
import os
import statistics as st

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402

R = os.path.join(os.path.dirname(__file__), "..", "results")
F = os.path.join(os.path.dirname(__file__), "..", "figures")
os.makedirs(F, exist_ok=True)
C = ["#2a78d6", "#eb6834", "#1baf7a", "#eda100", "#e87ba4"]
MK = ["o", "s", "^", "D", "v"]
LS = ["-", "--", "-.", ":", (0, (5, 1, 1, 1))]
INK, INK2, GRID = "#0b0b0b", "#52514e", "#e4e3df"
plt.rcParams.update({
    "font.family": "serif", "font.size": 8, "axes.titlesize": 8, "axes.labelsize": 8, "xtick.labelsize": 7,
    "ytick.labelsize": 7, "legend.fontsize": 6.5, "axes.edgecolor": INK2, "axes.labelcolor": INK,
    "xtick.color": INK2, "ytick.color": INK2, "axes.grid": True, "grid.color": GRID, "grid.linewidth": 0.5,
    "axes.spines.top": False, "axes.spines.right": False, "lines.linewidth": 1.3, "lines.markersize": 3.5,
    "pdf.fonttype": 42})
W = 3.45


def lbl(s):
    return f"{s // 1024}K" if s >= 1024 else str(s)


def fig_crypto(S):
    cr = S["crypto"]
    modes = ["None", "ASCON-128", "AES+Mask", "AES-GCM", "AES+PHE"]
    sizes = sorted({int(k.split("|")[1]) for k in cr["modes"]})
    fig, axs = plt.subplots(1, 2, figsize=(W * 2, 1.65))
    ax = axs[0]
    for i, m in enumerate(modes):
        ax.plot(sizes, [cr["modes"][f"{m}|{s}"]["enc_us"]["mean"] for s in sizes], color=C[i], marker=MK[i],
                linestyle=LS[i], label=m)
    ax.set_xscale("log", base=2); ax.set_yscale("log")
    ax.set_xticks(sizes); ax.set_xticklabels([lbl(s) for s in sizes])
    ax.set_xlabel("Payload size (bytes)"); ax.set_ylabel("Encryption time (µs)")
    ax.set_title("(a) Cost per mode (AES-NI gateway)")
    ax.legend(ncol=3, frameon=False, loc="upper left", bbox_to_anchor=(0.0, 0.86), fontsize=6.2)
    ax = axs[1]
    nb = cr["noaesni"]
    ns = sorted(int(k) for k in nb)
    ax.plot(ns, [cr["modes"][f"AES-GCM|{s}"]["enc_us"]["mean"] for s in ns], color=C[3], marker=MK[3], linestyle=LS[3],
            label="AES-GCM (AES-NI)")
    ax.plot(ns, [nb[str(s)]["aes_sw_us"]["mean"] for s in ns], color=C[0], marker=MK[0], linestyle=LS[0],
            label="AES-GCM (software)")
    ax.plot(ns, [nb[str(s)]["ascon_us"]["mean"] for s in ns], color=C[1], marker=MK[1], linestyle=LS[1], label="ASCON-AEAD128")
    ax.set_xscale("log", base=2); ax.set_yscale("log")
    ax.set_xticks(ns); ax.set_xticklabels([lbl(s) for s in ns])
    ax.set_xlabel("Payload size (bytes)"); ax.set_ylabel("Encryption time (µs)")
    ax.set_title("(b) ASCON vs AES-GCM, with/without AES-NI")
    ax.legend(frameon=False, loc="upper left")
    fig.tight_layout()
    fig.savefig(f"{F}/fig_crypto.pdf"); fig.savefig(f"{F}/fig_crypto.png", dpi=200)


def fig_dynamic():
    d = json.load(open(f"{R}/e8_dynamic.json"))
    b0, b1 = d["config"]["BURST"]
    fig, axs = plt.subplots(2, 1, figsize=(W, 2.35), sharex=True)
    for i, pol in enumerate(("static", "adaptive")):
        runs = [r["series"] for r in d["runs"] if r["policy"] == pol]
        T = [p["t"] for p in runs[0]]

        def avg(key):
            out = []
            for j in range(len(T)):
                v = [r[j][key] for r in runs if r[j][key] is not None]
                out.append(st.mean(v) if v else None)
            return out
        lat = avg("wear_lat_med")
        phe = avg("phe_share")
        name = "Static (all Paillier)" if pol == "static" else "Adaptive"
        axs[0].plot([t for t, v in zip(T, lat) if v], [v / 1e3 for v in lat if v], color=C[i], linestyle=LS[i],
                    label=name)
        axs[1].plot([t for t, v in zip(T, phe) if v is not None], [100 * v for v in phe if v is not None],
                    color=C[i], linestyle=LS[i], label=name)
    for ax in axs:
        ax.axvspan(b0, b1, color="#e4e3df", alpha=0.6, lw=0)
    axs[0].axhline(10, color=INK2, linestyle=(0, (2, 2)), linewidth=0.8, label="10 s budget")
    axs[0].set_yscale("log")
    axs[0].set_ylabel("Latency (s)")
    axs[0].set_ylim(0.01, 80)
    axs[1].legend(*axs[0].get_legend_handles_labels(), frameon=False, loc="center left", bbox_to_anchor=(0.0, 0.45), fontsize=6.0)
    axs[1].text((b0 + b1) / 2, 8, "wearable burst", ha="center", fontsize=6, color=INK2)
    axs[1].set_ylabel("Paillier (%)")
    axs[1].set_ylim(-5, 105)
    axs[1].set_xlabel("Time (s)")
    fig.align_ylabels(axs)
    fig.tight_layout(h_pad=0.4)
    fig.savefig(f"{F}/fig_dynamic.pdf"); fig.savefig(f"{F}/fig_dynamic.png", dpi=200)


if __name__ == "__main__":
    S = json.load(open(f"{R}/summary_v2.json"))
    fig_crypto(S)
    if os.path.exists(f"{R}/e8_dynamic.json"):
        fig_dynamic()
    print("figures written")
