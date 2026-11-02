"""Cryptographic primitives for the five protection modes, plus key wrapping.

Modes
  0 NONE      plaintext (integrity only, via the on-chain hash)
  1 ASCON     ASCON-AEAD128 (NIST SP 800-232), 128-bit key, optimized C (ascon-c opt64)
  2 AES_MASK  identifiers pseudonymised with HMAC-SHA256 tokens, remaining payload AES-256-GCM
  3 AES       AES-256-GCM over the whole payload
  4 AES_PHE   selected numeric fields Paillier-2048 (additively homomorphic), rest AES-256-GCM
"""
import ctypes
import hashlib
import hmac
import math
import os
import secrets

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from bnmath import powmod

NONE, ASCON, AES_MASK, AES, AES_PHE = 0, 1, 2, 3, 4
MODE_NAMES = {NONE: "None", ASCON: "ASCON-128", AES_MASK: "AES+Mask", AES: "AES-GCM", AES_PHE: "AES+PHE"}

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# ------------------------------- ASCON -----------------------------------
_ascon = ctypes.CDLL(os.path.join(ROOT, "lib", "libascon.so"))
_ull = ctypes.c_ulonglong
_ascon.crypto_aead_encrypt.argtypes = [ctypes.c_char_p, ctypes.POINTER(_ull), ctypes.c_char_p, _ull,
                                       ctypes.c_char_p, _ull, ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p]
_ascon.crypto_aead_decrypt.argtypes = [ctypes.c_char_p, ctypes.POINTER(_ull), ctypes.c_char_p, ctypes.c_char_p, _ull,
                                       ctypes.c_char_p, _ull, ctypes.c_char_p, ctypes.c_char_p]


def ascon_encrypt(key: bytes, nonce: bytes, ad: bytes, pt: bytes) -> bytes:
    out = ctypes.create_string_buffer(len(pt) + 16)
    clen = _ull(0)
    rc = _ascon.crypto_aead_encrypt(out, ctypes.byref(clen), pt, len(pt), ad, len(ad), None, nonce, key)
    assert rc == 0
    return out.raw[:clen.value]


def ascon_decrypt(key: bytes, nonce: bytes, ad: bytes, ct: bytes) -> bytes:
    out = ctypes.create_string_buffer(max(len(ct), 1))
    mlen = _ull(0)
    rc = _ascon.crypto_aead_decrypt(out, ctypes.byref(mlen), None, ct, len(ct), ad, len(ad), nonce, key)
    if rc != 0:
        raise ValueError("ASCON authentication failed")
    return out.raw[:mlen.value]


# ------------------------------ AES-GCM -----------------------------------
def aes_encrypt(key: bytes, nonce: bytes, ad: bytes, pt: bytes) -> bytes:
    return AESGCM(key).encrypt(nonce, pt, ad)


def aes_decrypt(key: bytes, nonce: bytes, ad: bytes, ct: bytes) -> bytes:
    return AESGCM(key).decrypt(nonce, ct, ad)


# ------------------------------ Masking -----------------------------------
def mask_token(mask_key: bytes, value: str) -> str:
    """Deterministic keyed pseudonym: same identifier -> same token (linkable), not reversible."""
    return hmac.new(mask_key, value.encode(), hashlib.sha256).hexdigest()[:32]


# ------------------------------ Paillier ----------------------------------
class PaillierPublic:
    def __init__(self, n: int):
        self.n = n
        self.n2 = n * n
        self.g = n + 1

    def encrypt(self, m: int) -> int:
        m %= self.n
        r = secrets.randbelow(self.n - 1) + 1
        # g^m = 1 + m*n (mod n^2) for g = n + 1
        return ((1 + m * self.n) % self.n2) * powmod(r, self.n, self.n2) % self.n2

    def add(self, c1: int, c2: int) -> int:
        return c1 * c2 % self.n2

    def mul_const(self, c: int, k: int) -> int:
        return powmod(c, k % self.n, self.n2)


class PaillierPrivate:
    """CRT decryption (Paillier 1999, Sec. 7)."""

    def __init__(self, pub: PaillierPublic, p: int, q: int):
        self.pub = pub
        self.p, self.q = p, q
        self.p2, self.q2 = p * p, q * q
        g = pub.g
        self.hp = pow(self._L(powmod(g, p - 1, self.p2), p), -1, p)
        self.hq = pow(self._L(powmod(g, q - 1, self.q2), q), -1, q)
        self.q_inv_p = pow(q, -1, p)

    @staticmethod
    def _L(x, d):
        return (x - 1) // d

    def decrypt(self, c: int) -> int:
        mp = self._L(powmod(c, self.p - 1, self.p2), self.p) * self.hp % self.p
        mq = self._L(powmod(c, self.q - 1, self.q2), self.q) * self.hq % self.q
        m = (mq + self.q * ((mp - mq) * self.q_inv_p % self.p)) % self.pub.n
        return m - self.pub.n if m > self.pub.n // 2 else m  # signed decoding


def paillier_keygen(bits=2048):
    k = rsa.generate_private_key(65537, bits)
    p, q = k.private_numbers().p, k.private_numbers().q
    pub = PaillierPublic(p * q)
    return pub, PaillierPrivate(pub, p, q)


FIXED_SCALE = 100  # two decimal places for fixed-point encoding of sensor values


def fp_encode(x: float) -> int:
    return int(round(x * FIXED_SCALE))


def fp_decode(m: int) -> float:
    return m / FIXED_SCALE


# ------------------------- Key wrapping -----------------------------------
# Hybrid KEM: X25519 (RFC 7748) + ML-KEM-768 (FIPS 203). The wrapping key is derived with
# HKDF-SHA256 over both shared secrets, so it stays secret if either primitive holds.
from cryptography.hazmat.primitives.asymmetric import mlkem  # noqa: E402

_INFO = b"adaptive-iot-wrap|"


class UserKeys:
    def __init__(self):
        self.x_sk = X25519PrivateKey.generate()
        self.k_sk = mlkem.MLKEM768PrivateKey.generate()
        self.pub = (self.x_sk.public_key(), self.k_sk.public_key())


def x25519_keypair():
    sk = X25519PrivateKey.generate()
    return sk, sk.public_key()


def _kek(ss: bytes, context: bytes) -> bytes:
    return HKDF(hashes.SHA256(), 32, salt=None, info=_INFO + context).derive(ss)


def wrap_key(recipient_pub, dek: bytes, context: bytes) -> bytes:
    """recipient_pub: X25519PublicKey (classical) or (X25519PublicKey, MLKEM768PublicKey) (hybrid)."""
    hybrid = isinstance(recipient_pub, tuple)
    x_pub = recipient_pub[0] if hybrid else recipient_pub
    eph = X25519PrivateKey.generate()
    ss = eph.exchange(x_pub)
    eph_raw = eph.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    kem_ct = b""
    if hybrid:
        ss_k, kem_ct = recipient_pub[1].encapsulate()
        ss = ss + ss_k
    nonce = os.urandom(12)
    return eph_raw + kem_ct + nonce + AESGCM(_kek(ss, context)).encrypt(nonce, dek, context)


def unwrap_key(recipient, blob: bytes, context: bytes) -> bytes:
    """recipient: X25519PrivateKey (classical) or UserKeys (hybrid)."""
    hybrid = isinstance(recipient, UserKeys)
    x_sk = recipient.x_sk if hybrid else recipient
    eph = X25519PublicKey.from_public_bytes(blob[:32])
    ss, off = x_sk.exchange(eph), 32
    if hybrid:
        ss += recipient.k_sk.decapsulate(blob[32:32 + 1088])
        off += 1088
    nonce, ct = blob[off:off + 12], blob[off + 12:]
    return AESGCM(_kek(ss, context)).decrypt(nonce, ct, context)
