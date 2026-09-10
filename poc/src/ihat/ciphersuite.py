"""The IHAT(P-256, SHA-256) ciphersuite."""

from __future__ import annotations

from dataclasses import dataclass
from typing import ClassVar, Generic, Protocol, Self, TypeAlias, TypeVar, cast, overload

from Cryptodome.Hash import SHA256
from Cryptodome.PublicKey import ECC
from Cryptodome.PublicKey.ECC import EccPoint

from .common import I2OSP


FIELD_MODULUS = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF
ORDER = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
CURVE_A = FIELD_MODULUS - 3
CURVE_B = 0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B
SSWU_Z = FIELD_MODULUS - 10
GENERATOR_X = 0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296
GENERATOR_Y = 0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5


class DeserializeError(ValueError):
    """A byte string is not a canonical encoding of the expected type."""


Suite = TypeVar("Suite")


@dataclass(frozen=True)
class Scalar(Generic[Suite]):
    """An element of the scalar field associated with Suite."""

    value: int
    order: ClassVar[int]

    def __post_init__(self) -> None:
        if self.value < 0 or self.value >= self.order:
            raise ValueError("scalar is out of range")

    def __int__(self) -> int:
        return self.value

    def __index__(self) -> int:
        return self.value

    def isZero(self) -> bool:
        return self.value == 0

    def __add__(self, other: Scalar[Suite]) -> Self:
        return cast(Self, type(self)((self.value + other.value) % self.order))

    def __radd__(self, other: Scalar[Suite]) -> Self:
        return self + other

    def __sub__(self, other: Scalar[Suite]) -> Self:
        return cast(Self, type(self)((self.value - other.value) % self.order))

    def __rsub__(self, other: Scalar[Suite]) -> Self:
        return cast(Self, other - self)

    @overload
    def __mul__(self, other: Scalar[Suite]) -> Self: ...

    @overload
    def __mul__(self, other: Element[Suite]) -> Element[Suite]: ...

    def __mul__(self, other: Scalar[Suite] | Element[Suite]) -> Self | Element[Suite]:
        return cast(Self | Element[Suite], other._left_scalar_multiply(self))

    def __rmul__(self, other: Scalar[Suite]) -> Self:
        return cast(Self, other * self)

    def _left_scalar_multiply(self, left: Scalar[Suite]) -> Self:
        return cast(Self, type(self)((left.value * self.value) % self.order))


class P256SHA256:
    """Phantom type identifying the IHAT(P-256, SHA-256) ciphersuite."""


class P256Scalar(Scalar[P256SHA256]):
    order = ORDER


def _sha256(data: bytes) -> bytes:
    return SHA256.new(data).digest()


def _xor(left: bytes, right: bytes) -> bytes:
    return bytes(a ^ b for a, b in zip(left, right, strict=True))


def expand_message_xmd(msg: bytes, dst: bytes, length: int) -> bytes:
    """RFC 9380 expand_message_xmd instantiated with SHA-256."""

    if len(dst) > 255:
        dst = _sha256(b"H2C-OVERSIZE-DST-" + dst)

    ell = (length + 31) // 32
    if ell > 255 or length > 65535:
        raise ValueError("invalid expand_message_xmd output length")

    dst_prime = dst + I2OSP(len(dst), 1)
    b0 = _sha256(bytes(64) + msg + I2OSP(length, 2) + b"\x00" + dst_prime)
    blocks = [_sha256(b0 + b"\x01" + dst_prime)]
    for counter in range(2, ell + 1):
        blocks.append(
            _sha256(_xor(b0, blocks[-1]) + I2OSP(counter, 1) + dst_prime)
        )
    return b"".join(blocks)[:length]


@dataclass(frozen=True)
class Element(Generic[Suite]):
    """A group element associated with Suite."""

    _point: EccPoint

    def __add__(self, other: Element[Suite]) -> Element[Suite]:
        return Element(self._point + other._point)

    def __sub__(self, other: Element[Suite]) -> Element[Suite]:
        return Element(self._point + (-other._point))

    def __mul__(self, scalar: Scalar[Suite]) -> Element[Suite]:
        return self._left_scalar_multiply(scalar)

    def __rmul__(self, scalar: Scalar[Suite]) -> Element[Suite]:
        return self * scalar

    def _left_scalar_multiply(self, scalar: Scalar[Suite]) -> Element[Suite]:
        return Element(self._point * scalar.value)

    def isIdentity(self) -> bool:
        return self._point.is_point_at_infinity()


P256Element: TypeAlias = Element[P256SHA256]


class PrimeOrderGroup(Protocol[Suite]):
    def scalar(self, value: int) -> Scalar[Suite]: ...

    def Identity(self) -> Element[Suite]: ...

    def Generator(self) -> Element[Suite]: ...

    def ScalarMultGen(self, scalar: Scalar[Suite]) -> Element[Suite]: ...


class P256Group(PrimeOrderGroup[P256SHA256]):
    """The group interface from the draft for one protocol context."""

    Ne = 33
    Ns = 32

    def __init__(self, ctx_proto: bytes):
        self.ctx_proto = bytes(ctx_proto)
        self._generator: Element[P256SHA256] = Element(
            EccPoint(GENERATOR_X, GENERATOR_Y, curve="p256")
        )

    def Order(self) -> int:
        return ORDER

    def scalar(self, value: int) -> P256Scalar:
        return P256Scalar(value)

    def Identity(self) -> Element[P256SHA256]:
        return Element(self._generator._point * 0)

    def Generator(self) -> Element[P256SHA256]:
        return Element(self._generator._point.copy())

    def ScalarMultGen(self, scalar: Scalar[P256SHA256]) -> Element[P256SHA256]:
        return scalar * self._generator

    def HashToGroup(
        self, value: bytes, *, DST: bytes | None = None
    ) -> Element[P256SHA256]:
        dst = DST if DST is not None else b"HashToGroup-" + self.ctx_proto
        uniform = expand_message_xmd(value, dst, 96)
        u0 = int.from_bytes(uniform[:48], "big") % FIELD_MODULUS
        u1 = int.from_bytes(uniform[48:], "big") % FIELD_MODULUS
        x0, y0 = self._map_to_curve_simple_swu(u0)
        x1, y1 = self._map_to_curve_simple_swu(u1)
        q0: Element[P256SHA256] = Element(EccPoint(x0, y0, curve="p256"))
        q1: Element[P256SHA256] = Element(EccPoint(x1, y1, curve="p256"))
        return q0 + q1

    def HashToScalar(self, value: bytes, *, DST: bytes | None = None) -> P256Scalar:
        dst = DST if DST is not None else b"HashToScalar-" + self.ctx_proto
        uniform = expand_message_xmd(value, dst, 48)
        return P256Scalar(int.from_bytes(uniform, "big") % ORDER)

    def ScalarInverse(self, scalar: Scalar[P256SHA256]) -> P256Scalar:
        if scalar.isZero():
            raise ZeroDivisionError("zero has no scalar inverse")
        return P256Scalar(pow(scalar.value, -1, ORDER))

    def SerializeElement(self, element: Element[P256SHA256]) -> bytes:
        if element.isIdentity():
            raise ValueError("the identity has no compressed SEC1 encoding")
        key = ECC.construct(
            curve="P-256", point_x=element._point.x, point_y=element._point.y
        )
        return key.export_key(format="SEC1", compress=True)

    def DeserializeElement(self, buf: bytes) -> Element[P256SHA256]:
        if len(buf) != self.Ne or buf[0] not in (2, 3):
            raise DeserializeError("invalid compressed P-256 element")
        x = int.from_bytes(buf[1:], "big")
        # ECC.import_key reduces out-of-range SEC1 coordinates modulo the field.
        # Reject them first so only canonical encodings are accepted.
        if x >= FIELD_MODULUS:
            raise DeserializeError("P-256 x-coordinate is out of range")
        try:
            key = ECC.import_key(buf, curve_name="P-256")
        except ValueError as error:
            raise DeserializeError("P-256 encoding is not on the curve") from error
        element: Element[P256SHA256] = Element(key.pointQ)
        if element.isIdentity():
            raise DeserializeError("the identity element is not allowed")
        return element

    def SerializeScalar(self, scalar: Scalar[P256SHA256]) -> bytes:
        return scalar.value.to_bytes(self.Ns, "big")

    def DeserializeScalar(self, buf: bytes) -> P256Scalar:
        if len(buf) != self.Ns:
            raise DeserializeError("invalid P-256 scalar length")
        scalar = int.from_bytes(buf, "big")
        if scalar >= ORDER:
            raise DeserializeError("P-256 scalar is out of range")
        return P256Scalar(scalar)

    def P(self, element: Element[P256SHA256]) -> Element[P256SHA256]:
        # SPEC: The P-256 permutation description has an incorrect SEC1 prefix
        # range and does not precisely define its cycle-walking inverse.
        raise NotImplementedError("the draft does not yet specify P unambiguously")

    def Pinv(self, element: Element[P256SHA256]) -> Element[P256SHA256]:
        # SPEC: Pinv is named but not algorithmically specified by the draft.
        raise NotImplementedError("the draft does not yet specify Pinv unambiguously")

    @staticmethod
    def _map_to_curve_simple_swu(u: int) -> tuple[int, int]:
        """RFC 9380 Appendix F.2 for P-256."""
        p = FIELD_MODULUS
        tv1 = SSWU_Z * u * u % p
        tv2 = tv1 * tv1 % p
        tv2 = (tv2 + tv1) % p
        tv3 = (tv2 + 1) * CURVE_B % p
        tv4 = SSWU_Z if tv2 == 0 else -tv2 % p
        tv4 = CURVE_A * tv4 % p
        tv2 = tv3 * tv3 % p
        tv6 = tv4 * tv4 % p
        tv5 = CURVE_A * tv6 % p
        tv2 = (tv2 + tv5) * tv3 % p
        tv6 = tv6 * tv4 % p
        tv5 = CURVE_B * tv6 % p
        tv2 = (tv2 + tv5) % p
        x = tv1 * tv3 % p
        is_square, y1 = P256Group._sqrt_ratio(tv2, tv6)
        y = tv1 * u * y1 % p
        if is_square:
            x, y = tv3, y1
        if (u & 1) != (y & 1):
            y = -y % p
        x = x * pow(tv4, -1, p) % p
        return x, y

    @staticmethod
    def _sqrt_ratio(u: int, v: int) -> tuple[bool, int]:
        p = FIELD_MODULUS
        tv1 = v * v % p
        tv2 = u * v % p
        tv1 = tv1 * tv2 % p
        y1 = pow(tv1, (p - 3) // 4, p) * tv2 % p
        y2 = y1 * pow(10, (p + 1) // 4, p) % p
        is_square = y1 * y1 % p * v % p == u
        return is_square, y1 if is_square else y2
