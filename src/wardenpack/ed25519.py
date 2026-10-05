"""Ed25519 (RFC 8032) signatures for registry indexes.

* Verification prefers the audited `cryptography` package when it is installed and falls back
  to a pure-Python RFC 8032 implementation, so the client keeps working with zero dependencies.
  Verification handles only public data, so the fallback's lack of constant-time arithmetic is
  not a secret-leak concern.
* Signing and key generation REQUIRE `cryptography` (pip install "wardenpack[sign]"): private
  keys are never handled by the pure-Python code.
"""
from __future__ import annotations

import hashlib

try:                                    # optional, preferred
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import (Ed25519PrivateKey,
                                                                   Ed25519PublicKey)
    HAVE_CRYPTOGRAPHY = True
except ImportError:                     # pragma: no cover
    HAVE_CRYPTOGRAPHY = False

P = 2**255 - 19
Q = 2**252 + 27742317777372353535851937790883648493
D = -121665 * pow(121666, P - 2, P) % P
SQRT_M1 = pow(2, (P - 1) // 4, P)


def _recover_x(y: int, sign: int):
    if y >= P:
        return None
    x2 = (y * y - 1) * pow(D * y * y + 1, P - 2, P)
    if x2 % P == 0:
        return None if sign else 0
    x = pow(x2, (P + 3) // 8, P)
    if (x * x - x2) % P:
        x = x * SQRT_M1 % P
    if (x * x - x2) % P:
        return None
    if (x & 1) != sign:
        x = P - x
    return x


_GY = 4 * pow(5, P - 2, P) % P
_GX = _recover_x(_GY, 0)
_G = (_GX, _GY, 1, _GX * _GY % P)


def _add(p1, p2):
    a = (p1[1] - p1[0]) * (p2[1] - p2[0]) % P
    b = (p1[1] + p1[0]) * (p2[1] + p2[0]) % P
    c = 2 * p1[3] * p2[3] * D % P
    d = 2 * p1[2] * p2[2] % P
    e, f, g, h = b - a, d - c, d + c, b + a
    return (e * f % P, g * h % P, f * g % P, e * h % P)


def _mul(s: int, pt):
    q = (0, 1, 1, 0)
    while s > 0:
        if s & 1:
            q = _add(q, pt)
        pt = _add(pt, pt)
        s >>= 1
    return q


def _equal(p1, p2) -> bool:
    return (p1[0] * p2[2] - p2[0] * p1[2]) % P == 0 and (p1[1] * p2[2] - p2[1] * p1[2]) % P == 0


def _decompress(s: bytes):
    if len(s) != 32:
        return None
    y = int.from_bytes(s, "little")
    sign, y = y >> 255, y & ((1 << 255) - 1)
    x = _recover_x(y, sign)
    return None if x is None else (x, y, 1, x * y % P)


def _verify_pure(public: bytes, msg: bytes, sig: bytes) -> bool:
    if len(public) != 32 or len(sig) != 64:
        return False
    a = _decompress(public)
    r = _decompress(sig[:32])
    s = int.from_bytes(sig[32:], "little")
    if a is None or r is None or s >= Q:
        return False
    h = int.from_bytes(hashlib.sha512(sig[:32] + public + msg).digest(), "little") % Q
    return _equal(_mul(s, _G), _add(r, _mul(h, a)))


def verify(public: bytes, msg: bytes, sig: bytes) -> bool:
    if HAVE_CRYPTOGRAPHY:
        try:
            Ed25519PublicKey.from_public_bytes(public).verify(sig, msg)
            return True
        except (InvalidSignature, ValueError):
            return False
    return _verify_pure(public, msg, sig)


def keyid(public: bytes) -> str:
    return hashlib.sha256(public).hexdigest()[:16]


def _need_crypto() -> None:
    if not HAVE_CRYPTOGRAPHY:
        raise RuntimeError('signing needs the "cryptography" package: pip install "wardenpack[sign]"')


def generate_keypair() -> tuple[bytes, bytes]:
    """Return (private_seed_32, public_32)."""
    _need_crypto()
    sk = Ed25519PrivateKey.generate()
    seed = sk.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw,
                            serialization.NoEncryption())
    pub = sk.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return seed, pub


def public_from_seed(seed: bytes) -> bytes:
    _need_crypto()
    return Ed25519PrivateKey.from_private_bytes(seed).public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw)


def sign(seed: bytes, msg: bytes) -> bytes:
    _need_crypto()
    return Ed25519PrivateKey.from_private_bytes(seed).sign(msg)
