"""Local transaction signing (EIP-155 legacy transactions) for clients such as Besu that do not
hold unlocked accounts. secp256k1 scalar multiplication is done by OpenSSL via `cryptography`;
the recovery id comes from the parity of R = kG, which the signer computes itself."""
import hashlib
import secrets
import threading

from cryptography.hazmat.primitives.asymmetric import ec

from chain import Chain

N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141


def keccak(b: bytes) -> bytes:
    h = hashlib.new("keccak-256")
    h.update(b)
    return h.digest()


def _rlp_item(b: bytes) -> bytes:
    if len(b) == 1 and b[0] < 0x80:
        return b
    return _rlp_len(len(b), 0x80) + b


def _rlp_len(n, off):
    if n < 56:
        return bytes([off + n])
    nb = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([off + 55 + len(nb)]) + nb


def rlp(x):
    if isinstance(x, list):
        body = b"".join(rlp(i) for i in x)
        return _rlp_len(len(body), 0xC0) + body
    if isinstance(x, int):
        x = b"" if x == 0 else x.to_bytes((x.bit_length() + 7) // 8, "big")
    return _rlp_item(x)


class Key:
    def __init__(self, d=None):
        self.d = d or (secrets.randbelow(N - 1) + 1)
        pub = ec.derive_private_key(self.d, ec.SECP256K1()).public_key().public_numbers()
        self.address = "0x" + keccak(pub.x.to_bytes(32, "big") + pub.y.to_bytes(32, "big"))[-20:].hex()

    def sign(self, digest: bytes):
        z = int.from_bytes(digest, "big")
        while True:
            k = secrets.randbelow(N - 1) + 1
            R = ec.derive_private_key(k, ec.SECP256K1()).public_key().public_numbers()
            r = R.x % N
            if r == 0:
                continue
            s = pow(k, -1, N) * (z + r * self.d) % N
            if s == 0:
                continue
            rec = R.y & 1
            if s > N // 2:          # low-s normalisation (EIP-2)
                s, rec = N - s, rec ^ 1
            return r, s, rec


class LocalChain(Chain):
    """Chain client that signs transactions locally and submits them raw."""

    def __init__(self, url, keys, gas_price=0):
        self.keys = {k.address.lower(): k for k in keys}
        self.gas_price = gas_price
        self.url = url
        self._id = 0
        self.accounts = [k.address for k in keys]
        self.chain_id = self.rpc("eth_chainId")
        self.cid = int(self.chain_id, 16)
        self._nonce = {}
        self._nlock = threading.Lock()
        self._alock = {}

    def submit(self, frm, to, data, gas=3_000_000):
        key = self.keys[frm.lower()]
        with self._acct_lock(frm):
            fk = frm.lower()
            if fk not in self._nonce:
                self._nonce[fk] = int(self.rpc("eth_getTransactionCount", [frm, "pending"]), 16)
            nonce = self._nonce[fk]
            to_b = bytes.fromhex(to[2:]) if to else b""
            payload = bytes.fromhex(data[2:])
            unsigned = [nonce, self.gas_price, gas, to_b, 0, payload, self.cid, 0, 0]
            r, s, rec = key.sign(keccak(rlp(unsigned)))
            raw = rlp([nonce, self.gas_price, gas, to_b, 0, payload, rec + 35 + 2 * self.cid, r, s])
            try:
                h = self.rpc("eth_sendRawTransaction", ["0x" + raw.hex()])
            except Exception:
                self._nonce.pop(fk, None)
                raise
            self._nonce[fk] = nonce + 1
            return h

    def deploy(self, frm, bytecode):
        rc = self.send(frm, None, "0x" + bytecode, gas=8_000_000)
        assert int(rc["status"], 16) == 1, rc
        return rc["contractAddress"], rc
