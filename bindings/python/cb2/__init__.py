"""Python bridge for cb2 over its C ABI, using ctypes only.

Point it at the shared library with the CB2_C_LIBRARY environment
variable, or install the library where the system finds it, or copy it
next to this package.
"""

from __future__ import annotations

from ._lib import lib
from .errors import Cb2Error, Code, LibraryNotFound, error_name
from .keys import LocalKey, PublicKey, RecipientKey, RecipientPublicKey, SecretKey
from .rules import Rules
from .tokens import Holder, KeyWrap, Local, Public, Seal, Token

__all__ = [
    "Cb2Error",
    "Code",
    "Holder",
    "KeyWrap",
    "LibraryNotFound",
    "Local",
    "LocalKey",
    "Public",
    "PublicKey",
    "RecipientKey",
    "RecipientPublicKey",
    "Rules",
    "Seal",
    "SecretKey",
    "Token",
    "error_name",
    "has_public",
    "has_seal",
    "version",
]


def version() -> str:
    """The version of the cb2 library behind the ABI."""
    return lib().cb2_version().decode("ascii")


def has_public() -> bool:
    """Whether this build carries cb2.public (ML-DSA)."""
    return lib().cb2_has_public() == 1


def has_seal() -> bool:
    """Whether this build carries kcb2.seal (X-Wing)."""
    return lib().cb2_has_seal() == 1
