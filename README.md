# Adaptive IoT Security Framework: Prototype and Experiments

Reference implementation for the paper *"AdaptiveTrust: Blockchain-Verified Adaptive Encryption and Threshold Key Release for IoT Data"* (L Dileep Sai and K Sagar, SRM University AP).

Edge gateways score each IoT record for sensitivity, resources and latency budget, pick one of five protection modes (None, ASCON-AEAD128, AES-256-GCM + HMAC masking, AES-256-GCM, AES-256-GCM + Paillier), store the envelope off-chain (SQLite / IPFS) and anchor its SHA-256 digest on-chain. The `AdaptiveTrust` contract validates every decision against a floor bound to the device's registered type, gates access with single-use grants, and quarantines records whose stored protection differs from the declared one (2-of-3 vote by key-release nodes). Data keys are Shamir-shared 2-of-3 across key-release (KRS) nodes and wrapped to users with hybrid X25519 + ML-KEM-768; Paillier fields use threshold decryption.

## Layout

```
contracts/AdaptiveTrust.sol   validate+anchor, access grants, tamper reports, KRS nodes, non-conformance quarantine
contracts/BareAnchor.sol      baseline: digest + reference only (gas comparison)
contracts/AnchorACL.sol       baseline: anchor + role-based access list (gas comparison)
contracts/NaiveTrust.sol      baseline: string-typed two-transaction design (gas comparison)
src/edge.py                   sensitivity / resource scores, decision engine (Alg. 1), workload generator
src/crypto_modes.py           the five modes; hybrid X25519/ML-KEM-768 key wrap (HKDF-SHA256)
src/threshold.py              Shamir sharing over GF(2^521-1); threshold Paillier (Shoup / Damgard-Jurik)
src/framework.py              Deployment, Gateway (key commitment, misbehaviour switches for tests),
                              KRS nodes (grant check, share release, evidence verification, voting), Client
src/env_setup.py              bring up chain + contract + KRS + storage for a benchmark
src/chain.py                  JSON-RPC client, ABI encoding, Anvil / Reth launchers
src/signer.py                 local secp256k1 / EIP-155 transaction signing (for Besu)
src/besu_net.py               4-validator Hyperledger Besu QBFT network launcher
src/bnmath.py                 OpenSSL BN_mod_exp binding used by Paillier
src/storage.py                SQLite store and IPFS (Kubo) client
bench/                        experiments, aggregation, figures (bench/legacy: first-version scripts)
results/                      raw JSON results; results/reps: one file per repetition
results/v1_superseded/        single-run results of the first version (not used in the paper)
figures/                      generated figures (PDF + PNG)
```

## Requirements

- Python 3.10+ with `cryptography` (>= 44, for ML-KEM) and `matplotlib`
- gcc (to build ASCON), OpenSSL 3 `libcrypto`, Java 21 (for Besu)
- Binaries in `tools/` (GitHub releases):
  - solc 0.8.24 — `tools/dl_solc/solc`
  - Foundry 1.5.1 (`anvil`, `cast`) — `tools/dl_foundry/`
  - Reth 1.9.3 — `tools/dl_reth/reth`
  - Hyperledger Besu 25.10.0 — `tools/dl_besu/besu-25.10.0/`
  - Kubo 0.32.1 — `tools/dl_kubo/kubo/ipfs`
- ASCON C code: `git clone https://github.com/ascon/ascon-c tools/dl_ascon/ascon-c`

On Windows, run everything inside WSL2 (Ubuntu).

## Build

```bash
# ASCON-AEAD128 (optimized 64-bit implementation)
D=tools/dl_ascon/ascon-c/crypto_aead/asconaead128/opt64
gcc -O3 -march=native -fPIC -shared -I$D $D/aead.c $D/permutations.c -o lib/libascon.so

# Contracts
tools/dl_solc/solc --optimize --optimize-runs 200 --combined-json abi,bin,hashes \
    contracts/AdaptiveTrust.sol contracts/BareAnchor.sol contracts/AnchorACL.sol contracts/NaiveTrust.sol \
    -o build --overwrite
```

## Run the experiments

Each benchmark starts and stops its own chain and IPFS daemon; run them one at a time.

| Script | Measures | Output |
|---|---|---|
| `for k in 1 2 3 4 5; do E1_OUT=reps/e1_crypto_r$k.json python3 bench/bench_crypto.py; done` | per-mode crypto cost, Paillier micro-costs | `results/reps/e1_crypto_r*.json` |
| `for k in 1 2 3 4 5; do E1B_OUT=reps/e1b_noaesni_r$k.json OPENSSL_ia32cap="~0x200000200000000" python3 bench/bench_noaesni.py; done` | ASCON vs software AES-GCM (AES-NI masked) | `results/reps/e1b_noaesni_r*.json` |
| `python3 bench/bench_keyops.py` | hybrid PQ key wrap, Shamir, threshold Paillier | `results/e1c_keyops.json` |
| `python3 bench/bench_security_gas.py` | gas (incl. baselines), 21 attack scenarios + KRS fault tests (Anvil) | `results/e3_e5_v2.json` |
| `python3 bench/bench_policy.py` | adaptive vs uniform policies, 3 seeds | `results/e6_policy_v2.json` |
| `RETH_OUT=reps/e2_e4_reth_r1.json python3 bench/bench_reth.py` (x3) | latency, inclusion, reads, throughput on Reth (1 s blocks) | `results/reps/e2_e4_reth_r*.json` |
| `bash bench/run_besu.sh` | the same on a 4-validator Besu QBFT network (10 rec/s) | `results/reps/e2_e4_besu_r*.json` |
| `REPS=3 python3 bench/bench_dynamic.py` | adaptation under a wearable burst, single-core gateway | `results/e8_dynamic.json` |
| `python3 bench/bench_sensitivity.py` | weights, thresholds, R_min, L_PHE | `results/e7_sensitivity.json` |
| `python3 bench/aggregate_v2.py && python3 bench/make_figures_v2.py` | mean ± sd across runs; figures | `results/summary_v2.json`, `figures/` |

`bench/run_all_v2.sh` runs security/gas, policy and the three Reth repetitions in sequence with cleanup in between.

## Notes on the measurement setup

- **Chains.** Latency and throughput come from Reth (dev mode, 1 s blocks) and from a 4-validator Besu QBFT network (1 s blocks). Anvil is used only for gas and pass/fail security outcomes, which are client-independent; it runs with `--prune-history` because its state snapshots otherwise fill tens of GB.
- **Besu on a small host.** All four validator JVMs and the gateway share the host's CPUs, so Besu runs at 10 rec/s and its asynchronous throughput (25–29 rec/s) is a bound of the host, not of QBFT.
- **KRS nodes** have separate master keys, share stores and chain accounts and verify grants independently, but run in one process in the prototype.
- **Keys.** The dev private keys in `src/chain.py` and `src/besu_net.py` are public test keys; never use them outside a private test network.
- All paper numbers come from a 2-vCPU Xeon (2.1 GHz, AES-NI), 8 GB RAM, Linux host. Expect different absolute numbers elsewhere; rerun and update the tables.

## Which result file backs which part of the paper

| Paper element | Source |
|---|---|
| Fig. 2, Paillier and key-management numbers | `results/reps/e1_crypto_r*.json`, `results/reps/e1b_noaesni_r*.json`, `results/e1c_keyops.json` |
| Table 3 (latency), throughput | `results/reps/e2_e4_reth_r*.json`, `results/reps/e2_e4_besu_r*.json` (aggregated in `summary_v2.json`) |
| Table 4 (gas), Table 6 (attacks), key-release overhead | `results/e3_e5_v2.json` |
| Table 5 (adaptive vs uniform) | `results/e6_policy_v2.json` |
| Fig. 3 (load burst) | `results/e8_dynamic.json` |
| Parameter sensitivity | `results/e7_sensitivity.json` |
