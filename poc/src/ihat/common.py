"""Functions shared by the IHAT and ACT implementations."""

import secrets


Nseed = 48


def I2OSP(value: int, length: int) -> bytes:
    if value < 0 or value >= 1 << (8 * length):
        raise ValueError("integer does not fit the requested length")
    return value.to_bytes(length, "big")


def U16Prefixed(value: bytes) -> bytes:
    return I2OSP(len(value), 2) + value


def CreateProtocolContext(identifier: bytes) -> bytes:
    return b"IHATv1-" + identifier


def random(n: int) -> bytes:
    """Return bytes from the operating system's cryptographic RNG."""
    return secrets.token_bytes(n)


def Seed(value: bytes, index: int) -> bytes:
    return value[index * Nseed : (index + 1) * Nseed]
