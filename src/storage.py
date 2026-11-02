"""Off-chain storage: SQLite for small structured telemetry, IPFS (Kubo HTTP API)
for large or content-addressed objects."""
import json
import os
import sqlite3
import subprocess
import threading
import time
import urllib.request
import uuid

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
IPFS_BIN = os.path.join(ROOT, "tools", "dl_kubo", "kubo", "ipfs")
_opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))


class IPFS:
    def __init__(self, api="http://127.0.0.1:5001"):
        self.api = api

    def add(self, data: bytes) -> str:
        boundary = uuid.uuid4().hex
        body = (f"--{boundary}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"obj\"\r\n"
                f"Content-Type: application/octet-stream\r\n\r\n").encode() + data + f"\r\n--{boundary}--\r\n".encode()
        req = urllib.request.Request(f"{self.api}/api/v0/add?cid-version=1&pin=true&quiet=true", data=body,
                                     headers={"Content-Type": f"multipart/form-data; boundary={boundary}"})
        with _opener.open(req, timeout=60) as r:
            return json.loads(r.read().decode().strip().splitlines()[-1])["Hash"]

    def cat(self, cid: str) -> bytes:
        req = urllib.request.Request(f"{self.api}/api/v0/cat?arg={cid}", method="POST")
        with _opener.open(req, timeout=60) as r:
            return r.read()


def start_ipfs(repo):
    env = dict(os.environ, IPFS_PATH=repo)
    if not os.path.exists(os.path.join(repo, "config")):
        subprocess.run([IPFS_BIN, "init", "--profile=test"], env=env, check=True, capture_output=True)
        subprocess.run([IPFS_BIN, "config", "Addresses.API", "/ip4/127.0.0.1/tcp/5001"], env=env, check=True)
    p = subprocess.Popen([IPFS_BIN, "daemon", "--offline"], env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    ipfs = IPFS()
    for _ in range(300):
        try:
            ipfs.add(b"ping")
            return p, ipfs
        except Exception:
            time.sleep(0.1)
    p.kill()
    raise RuntimeError("ipfs did not start")


class SQLStore:
    def __init__(self, path):
        self.path = path
        self._lock = threading.Lock()
        self.db = sqlite3.connect(path, check_same_thread=False)
        self.db.execute("PRAGMA journal_mode=WAL")
        self.db.execute("CREATE TABLE IF NOT EXISTS objects (id INTEGER PRIMARY KEY, data BLOB)")
        self.db.commit()

    def put(self, data: bytes) -> str:
        with self._lock:
            cur = self.db.execute("INSERT INTO objects (data) VALUES (?)", (data,))
            self.db.commit()
            return f"sqlite:objects:{cur.lastrowid}"

    def get(self, ref: str) -> bytes:
        rid = int(ref.split(":")[-1])
        with self._lock:
            row = self.db.execute("SELECT data FROM objects WHERE id=?", (rid,)).fetchone()
        return row[0]

    def overwrite(self, ref: str, data: bytes):
        """Used only by the tamper experiments to simulate an insider modifying storage."""
        rid = int(ref.split(":")[-1])
        with self._lock:
            self.db.execute("UPDATE objects SET data=? WHERE id=?", (data, rid))
            self.db.commit()
