"""Bring up Anvil + IPFS, deploy and configure the trust contract."""
import atexit
import os
import shutil

import crypto_modes as cm
from chain import start_anvil, start_reth
from framework import Deployment, Gateway, KeyReleaseService, Client
from storage import SQLStore, start_ipfs

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RUN = os.path.join(ROOT, "run")


def bring_up(block_time=None, fresh=True, port=8545, client="anvil", n_krs=3, t_krs=2, url=None, chain=None):
    os.makedirs(RUN, exist_ok=True)
    if url is None and chain is None:
        if client == "reth":
            node, url = start_reth(port=port, block_time=block_time)
        else:
            node, url = start_anvil(port=port, block_time=block_time)
        atexit.register(node.kill)
    repo = os.path.join(RUN, f"ipfs-repo-{port}")
    if fresh and os.path.exists(repo):
        shutil.rmtree(repo)
    ipfs_p, ipfs = start_ipfs(repo)
    atexit.register(ipfs_p.kill)
    dbp = os.path.join(RUN, f"store-{port}.db")
    for suffix in ("", "-wal", "-shm"):
        if os.path.exists(dbp + suffix):
            os.remove(dbp + suffix)
    sql = SQLStore(dbp)
    dep = Deployment(url, n_krs=n_krs, t_krs=t_krs, chain=chain)
    dep.configure()
    phe_pub, phe_priv = cm.paillier_keygen(2048)
    holder = {}
    krs = KeyReleaseService(dep, phe_pub, phe_priv.p, phe_priv.q, storage=lambda d: holder["gw"].storage_view(d))
    krs.holder = holder
    return dep, krs, phe_pub, sql, ipfs


def make_gateway(dep, krs, phe_pub, sql, ipfs, idx=0, **kw):
    gw = Gateway(dep, dep.edge_accounts[idx], krs, phe_pub, sql, ipfs, **kw)
    krs.holder.setdefault("gw", gw)
    return gw
