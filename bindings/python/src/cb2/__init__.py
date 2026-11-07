"""cb2 tokens for Python over the cb2_c shared library, using ctypes only.

A wheel bundles the shared library inside this package. The
CB2_C_LIBRARY environment variable overrides it with an explicit path,
and without a bundled copy the system library path is searched. The
library is opened on first use; library_path() says which file it was.
"""

from __future__ import annotations

from ._lib import loaded
from .errors import Cb2Error, Code, LibraryNotFound, error_name
from .keys import LocalKey, PublicKey, RecipientKey, RecipientPublicKey, SecretKey
from .rules import ReplayCheck, Rules, RulesLike
from .tokens import Claims, Compact, Holder, KeyWrap, Local, Public, Seal, Token

__version__ = "0.1.0"

__all__ = [
    "Cb2Error",
    "Claims",
    "Code",
    "Compact",
    "Holder",
    "KeyWrap",
    "LibraryNotFound",
    "Local",
    "LocalKey",
    "Public",
    "PublicKey",
    "RecipientKey",
    "RecipientPublicKey",
    "ReplayCheck",
    "Rules",
    "RulesLike",
    "Seal",
    "SecretKey",
    "Token",
    "__version__",
    "error_name",
    "has_public",
    "has_seal",
    "library_path",
    "version",
]


def version() -> str:
    """The version of the cb2 library behind the ABI."""
    raw: bytes = loaded().cdll.cb2_version()
    return raw.decode("ascii")


def has_public() -> bool:
    """Whether this build carries cb2.public (Ed25519 + ML-DSA-65)."""
    return bool(loaded().cdll.cb2_has_public() == 1)


def has_seal() -> bool:
    """Whether this build carries kcb2.seal (X-Wing)."""
    return bool(loaded().cdll.cb2_has_seal() == 1)


def library_path() -> str:
    """The path of the cb2_c shared library this process opened."""
    return loaded().path
