"""Modular exponentiation through OpenSSL libcrypto (BN_mod_exp), so Paillier
runs on the same native big-number backend as the rest of the crypto stack."""
import ctypes
import ctypes.util

_lib = ctypes.CDLL(ctypes.util.find_library("crypto") or "libcrypto.so.3")
_vp = ctypes.c_void_p
_lib.BN_new.restype = _vp
_lib.BN_CTX_new.restype = _vp
_lib.BN_bin2bn.restype = _vp
_lib.BN_bin2bn.argtypes = [ctypes.c_char_p, ctypes.c_int, _vp]
_lib.BN_bn2bin.argtypes = [_vp, ctypes.c_char_p]
_lib.BN_num_bits.argtypes = [_vp]
_lib.BN_mod_exp.argtypes = [_vp, _vp, _vp, _vp, _vp]
_lib.BN_free.argtypes = [_vp]
_lib.BN_CTX_free.argtypes = [_vp]

import threading
_tls = threading.local()


def _ctx():
    c = getattr(_tls, "ctx", None)
    if c is None:
        c = _tls.ctx = _lib.BN_CTX_new()
    return c


def _to_bn(x: int):
    b = x.to_bytes(max(1, (x.bit_length() + 7) // 8), "big")
    return _lib.BN_bin2bn(b, len(b), None)


def _from_bn(bn) -> int:
    nbytes = (_lib.BN_num_bits(bn) + 7) // 8
    buf = ctypes.create_string_buffer(max(nbytes, 1))
    _lib.BN_bn2bin(bn, buf)
    return int.from_bytes(buf.raw[:nbytes], "big") if nbytes else 0


def powmod(base: int, exp: int, mod: int) -> int:
    a, e, m, r = _to_bn(base % mod), _to_bn(exp), _to_bn(mod), _lib.BN_new()
    try:
        if _lib.BN_mod_exp(r, a, e, m, _ctx()) != 1:
            raise RuntimeError("BN_mod_exp failed")
        return _from_bn(r)
    finally:
        for b in (a, e, m, r):
            _lib.BN_free(b)
