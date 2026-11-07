"""The verdicts of the library as Python exceptions."""

from __future__ import annotations

from enum import IntEnum


class Code(IntEnum):
    """The error codes of the C ABI; 0 is success."""

    OK = 0
    INVALID = 1
    TOO_LARGE = 2
    ARGUMENT = 3
    RULES_INCOMPLETE = 4
    INTERNAL = 5
    UNAVAILABLE = 6
    CLAIMS_MALFORMED = 7
    MISSING_EXP = 8
    EXPIRED = 9
    NOT_YET_VALID = 10
    ISSUED_IN_FUTURE = 11
    LIFETIME_EXCEEDED = 12
    ISSUER_MISMATCH = 13
    AUDIENCE_MISMATCH = 14
    SUBJECT_MISMATCH = 15
    MISSING_JTI = 16
    REPLAYED = 17
    MISSING_CNF = 18
    MISSING_PROOF = 19
    PROOF_INVALID = 20
    PROOF_MALFORMED = 21
    PROOF_EXPIRED = 22
    PROOF_MISMATCH = 23
    PROOF_REPLAYED = 24


class LibraryNotFound(OSError):
    """Raised when the cb2_c shared library cannot be located or opened."""


class Cb2Error(Exception):
    """A verdict of the library: code is the integer, name its stable text."""

    code: int
    name: str

    def __init__(self, code: int, name: str) -> None:
        super().__init__(f"cb2: {name} ({int(code)})")
        self.code = int(code)
        self.name = name

    def __reduce__(self) -> tuple[type[Cb2Error], tuple[int, str]]:
        return (Cb2Error, (self.code, self.name))


def error_name(code: int) -> str:
    """The stable name of a code, "ok" for 0 and "unknown" for unknown codes."""
    from ._lib import lib

    raw: bytes = lib().cb2_error_name(int(code))
    return raw.decode("ascii")


def check(code: int) -> None:
    """Raises Cb2Error for any non-zero code."""
    if code != 0:
        raise Cb2Error(code, error_name(code))
