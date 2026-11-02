"""Threshold primitives for a distributed key-release service.

* Shamir t-of-n sharing of 256-bit data keys over GF(P), P = 2^521 - 1.
* Threshold Paillier decryption (Shoup / Damgard-Jurik technique): the decryption
  exponent d (d = 0 mod lambda, d = 1 mod n) is Shamir-shared over the integers with
  Delta = n_nodes!; node i returns c^(2*Delta*s_i) mod n^2 and any t partials combine to
  c^(4*Delta^2*d) = 1 + 4*Delta^2*m*n (mod n^2).
"""
import math
import secrets

from bnmath import powmod

P521 = (1 << 521) - 1


# ------------------------------ Shamir over GF(P) ------------------------------
def shamir_split(secret: bytes, n: int, t: int):
    s = int.from_bytes(secret, "big")
    coeffs = [s] + [secrets.randbelow(P521) for _ in range(t - 1)]
    shares = []
    for x in range(1, n + 1):
        y = 0
        for c in reversed(coeffs):
            y = (y * x + c) % P521
        shares.append((x, y))
    return shares


def shamir_combine(shares, length=32) -> bytes:
    s = 0
    for i, (xi, yi) in enumerate(shares):
        num, den = 1, 1
        for j, (xj, _) in enumerate(shares):
            if i != j:
                num = num * (-xj) % P521
                den = den * (xi - xj) % P521
        s = (s + yi * num * pow(den, -1, P521)) % P521
    return s.to_bytes(length, "big") if s < (1 << (8 * length)) else s.to_bytes((s.bit_length() + 7) // 8, "big")


# ------------------------------ Threshold Paillier ------------------------------
class ThresholdPaillier:
    def __init__(self, pub, p: int, q: int, n_nodes: int, t: int, stat_sec=128):
        self.pub, self.n_nodes, self.t = pub, n_nodes, t
        n = pub.n
        lam = (p - 1) * (q - 1) // math.gcd(p - 1, q - 1)
        d = lam * pow(lam, -1, n)            # d = 0 mod lam, d = 1 mod n
        self.delta = math.factorial(n_nodes)
        bound = n * lam * (1 << stat_sec)    # statistical hiding of d
        coeffs = [d] + [secrets.randbelow(bound) for _ in range(t - 1)]
        self.shares = {}
        for x in range(1, n_nodes + 1):
            self.shares[x] = sum(c * x ** k for k, c in enumerate(coeffs))
        self.inv4d2 = pow(4 * self.delta * self.delta, -1, n)

    def partial(self, idx: int, c: int) -> int:
        """Run by KRS node idx with its own share."""
        return powmod(c, 2 * self.delta * self.shares[idx], self.pub.n2)

    def combine(self, partials: dict) -> int:
        n2, n = self.pub.n2, self.pub.n
        S = list(partials)
        acc = 1
        for i in S:
            num, den = self.delta, 1
            for j in S:
                if j != i:
                    num *= -j
                    den *= (i - j)
            lam_i = num // den                 # exact: Delta makes it an integer
            e = 2 * lam_i
            base = partials[i] if e >= 0 else pow(partials[i], -1, n2)
            acc = acc * powmod(base, abs(e), n2) % n2
        m = ((acc - 1) // n) * self.inv4d2 % n
        return m - n if m > n // 2 else m
