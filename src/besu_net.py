"""Start a 4-validator Hyperledger Besu QBFT network (1 s blocks, 36 M gas limit, Cancun rules,
zero base fee) on localhost and return a locally-signing chain client."""
import atexit
import glob
import json
import os
import shutil
import subprocess
import time

from signer import Key, LocalChain

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BESU = os.path.join(ROOT, "tools", "dl_besu", "besu-25.10.0", "bin", "besu")
DEV_KEYS = [int.from_bytes(bytes.fromhex(h), "big") for h in (
    # deterministic test keys (never use outside a private test network)
    *(format(0x1000 + i, "064x") for i in range(20)),)]


def start(n_validators=4, block_period=1, base_rpc=8645, base_p2p=30403, workdir=None, heap="640m"):
    workdir = workdir or os.path.join(ROOT, "run", "besu")
    if os.path.exists(workdir):
        shutil.rmtree(workdir)
    os.makedirs(workdir)
    keys = [Key(d) for d in DEV_KEYS]
    cfg = {
        "genesis": {
            "config": {"chainId": 1337, "berlinBlock": 0, "londonBlock": 0, "shanghaiTime": 0, "cancunTime": 0,
                       "zeroBaseFee": True, "contractSizeLimit": 50000,
                       "qbft": {"blockperiodseconds": block_period, "epochlength": 30000, "requesttimeoutseconds": 4}},
            "nonce": "0x0", "timestamp": "0x58ee40ba", "gasLimit": hex(36_000_000), "difficulty": "0x1",
            "mixHash": "0x63746963616c2062797a616e74696e65206661756c7420746f6c6572616e6365",
            "coinbase": "0x0000000000000000000000000000000000000000",
            "alloc": {k.address[2:]: {"balance": hex(10 ** 24)} for k in keys},
        },
        "blockchain": {"nodes": {"generate": True, "count": n_validators}},
    }
    with open(os.path.join(workdir, "qbft.json"), "w") as f:
        json.dump(cfg, f)
    env = dict(os.environ, BESU_OPTS=f"-Xmx{heap}", JAVA_OPTS=f"-Xmx{heap}")
    subprocess.run([BESU, "operator", "generate-blockchain-config", f"--config-file={workdir}/qbft.json",
                    f"--to={workdir}/net", "--private-key-file-name=key"], check=True, env=env,
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    node_keys = sorted(glob.glob(f"{workdir}/net/keys/*"))
    procs, enode0 = [], None
    for i, kd in enumerate(node_keys):
        nd = os.path.join(workdir, f"node{i}")
        os.makedirs(nd)
        shutil.copy(os.path.join(kd, "key"), os.path.join(nd, "key"))
        pub = open(os.path.join(kd, "key.pub")).read().strip()[2:]
        if i == 0:
            enode0 = f"enode://{pub}@127.0.0.1:{base_p2p}"
        args = [BESU, f"--data-path={nd}/data", f"--genesis-file={workdir}/net/genesis.json",
                f"--node-private-key-file={nd}/key", f"--p2p-port={base_p2p + i}", "--p2p-host=127.0.0.1",
                "--rpc-http-enabled", "--rpc-http-api=ETH,NET,QBFT,WEB3,TXPOOL", f"--rpc-http-port={base_rpc + i}",
                "--host-allowlist=*", "--min-gas-price=0", "--discovery-enabled=false",
                "--tx-pool-max-future-by-sender=10000", "--tx-pool-layer-max-capacity=200000000",
                "--logging=ERROR", "--data-storage-format=BONSAI", "--sync-min-peers=1"]
        if i > 0:
            args.append(f"--bootnodes={enode0}")
            args.append(f"--static-nodes-file={workdir}/static.json")
        if i == 0:
            json.dump([f"enode://{open(os.path.join(k, 'key.pub')).read().strip()[2:]}@127.0.0.1:{base_p2p + j}"
                       for j, k in enumerate(node_keys)], open(f"{workdir}/static.json", "w"))
            args.append(f"--static-nodes-file={workdir}/static.json")
        procs.append(subprocess.Popen(args, env=env, stdout=open(f"{nd}/log.txt", "w"), stderr=subprocess.STDOUT,
                                      start_new_session=True))
    atexit.register(stop, procs)
    url = f"http://127.0.0.1:{base_rpc}"
    for _ in range(600):
        try:
            ch = LocalChain(url, keys)
            if int(ch.rpc("eth_blockNumber"), 16) >= 3 and int(ch.rpc("net_peerCount"), 16) >= n_validators - 1:
                return procs, ch
        except Exception:
            pass
        time.sleep(0.5)
    raise RuntimeError("besu network did not start")


def stop(procs):
    """Kill each node's whole process group (the besu launcher script and its JVM)."""
    import signal
    for p in procs:
        try:
            os.killpg(os.getpgid(p.pid), signal.SIGKILL)
        except (ProcessLookupError, PermissionError):
            pass
