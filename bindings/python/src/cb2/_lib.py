"""Locates and loads the cb2_c shared library and declares every prototype it exports."""

from __future__ import annotations

import ctypes
import ctypes.util
import functools
import os
import sys
from ctypes import CFUNCTYPE, POINTER, c_char_p, c_int, c_int64, c_size_t, c_void_p
from pathlib import Path
from typing import Any, NamedTuple

from .errors import LibraryNotFound

ENV_VAR = "CB2_C_LIBRARY"
ABI_VERSION = 0

ReplayFn = CFUNCTYPE(c_int, c_void_p, c_char_p, c_size_t)

BytesLike = str | bytes | bytearray | memoryview

_PTR_OUT = POINTER(c_void_p)
_LEN_OUT = POINTER(c_size_t)

_KEY_TYPES = ("local_key", "secret_key", "public_key", "recipient_key", "recipient_public_key")

_RAW = [c_void_p, c_char_p, c_size_t, c_char_p, c_size_t, c_char_p, c_size_t]
_CLAIMS_READ = [*_RAW, ReplayFn, ReplayFn, c_void_p, _PTR_OUT, _LEN_OUT]
_PROVE = [c_void_p, *([c_char_p, c_size_t] * 5), c_int64, c_int64, _PTR_OUT, _LEN_OUT]

_PROTOTYPES: dict[str, tuple[Any, list[Any]]] = {
    "cb2_version": (c_char_p, []),
    "cb2_abi_version": (c_int, []),
    "cb2_has_public": (c_int, []),
    "cb2_has_seal": (c_int, []),
    "cb2_error_name": (c_char_p, [c_int]),
    "cb2_free": (None, [c_void_p]),
    "cb2_free_secret": (None, [c_void_p]),
    "cb2_local_key_generate": (c_int, [_PTR_OUT]),
    "cb2_secret_key_generate": (c_int, [_PTR_OUT]),
    "cb2_recipient_key_generate": (c_int, [_PTR_OUT]),
    "cb2_secret_key_public_key": (c_int, [c_void_p, _PTR_OUT]),
    "cb2_recipient_key_public_key": (c_int, [c_void_p, _PTR_OUT]),
    "cb2_local_key_paserk_id": (c_void_p, [c_void_p]),
    "cb2_public_key_paserk_id": (c_void_p, [c_void_p]),
    "cb2_recipient_key_paserk_id": (c_void_p, [c_void_p]),
    "cb2_recipient_public_key_paserk_id": (c_void_p, [c_void_p]),
    "cb2_local_seal": (c_int, [*_RAW, _PTR_OUT, _LEN_OUT]),
    "cb2_local_open": (c_int, [*_RAW, c_size_t, _PTR_OUT, _LEN_OUT]),
    "cb2_public_sign": (c_int, [*_RAW, _PTR_OUT, _LEN_OUT]),
    "cb2_public_verify": (c_int, [*_RAW, c_size_t, _PTR_OUT, _LEN_OUT]),
    "cb2_token_seal": (c_int, [c_void_p, c_char_p, c_size_t, c_char_p, c_size_t, _PTR_OUT, _LEN_OUT]),
    "cb2_token_sign": (c_int, [c_void_p, c_char_p, c_size_t, c_char_p, c_size_t, _PTR_OUT, _LEN_OUT]),
    "cb2_token_open": (c_int, _CLAIMS_READ),
    "cb2_token_verify": (c_int, _CLAIMS_READ),
    "cb2_peek_key_id": (c_int, [c_char_p, c_size_t, _PTR_OUT]),
    "cb2_compact_seal": (c_int, [c_void_p, c_char_p, c_size_t, c_char_p, c_size_t, _PTR_OUT, _LEN_OUT]),
    "cb2_compact_sign": (c_int, [c_void_p, c_char_p, c_size_t, c_char_p, c_size_t, _PTR_OUT, _LEN_OUT]),
    "cb2_compact_open": (c_int, _CLAIMS_READ),
    "cb2_compact_verify": (c_int, _CLAIMS_READ),
    "cb2_compact_peek_key_digest": (c_int, [c_char_p, c_size_t, _PTR_OUT]),
    "cb2_compact_key_digest": (c_int, [c_char_p, c_size_t, _PTR_OUT]),
    "cb2_holder_prove": (c_int, _PROVE),
    "cb2_holder_prove_local": (c_int, _PROVE),
    "cb2_holder_normalize_target": (c_int, [c_char_p, c_size_t, _PTR_OUT]),
    "cb2_wrap": (c_int, [c_void_p, c_void_p, _PTR_OUT]),
    "cb2_unwrap": (c_int, [c_char_p, c_size_t, c_void_p, _PTR_OUT]),
    "cb2_seal": (c_int, [c_void_p, c_void_p, _PTR_OUT]),
    "cb2_unseal": (c_int, [c_char_p, c_size_t, c_void_p, _PTR_OUT]),
}

for _kind in _KEY_TYPES:
    _PROTOTYPES[f"cb2_{_kind}_from_bytes"] = (c_int, [c_char_p, c_size_t, _PTR_OUT])
    _PROTOTYPES[f"cb2_{_kind}_from_paserk"] = (c_int, [c_char_p, c_size_t, _PTR_OUT])
    _PROTOTYPES[f"cb2_{_kind}_to_paserk"] = (c_void_p, [c_void_p])
    _PROTOTYPES[f"cb2_{_kind}_free"] = (None, [c_void_p])

for _kind in ("local_key", "secret_key", "public_key"):
    _PROTOTYPES[f"cb2_{_kind}_key_id"] = (c_void_p, [c_void_p])
    _PROTOTYPES[f"cb2_{_kind}_set_key_id"] = (c_int, [c_void_p, c_char_p, c_size_t])
    _PROTOTYPES[f"cb2_{_kind}_clear_key_id"] = (None, [c_void_p])


class Loaded(NamedTuple):
    """The opened library and the path it was opened from."""

    cdll: ctypes.CDLL
    path: str


_NAMES = {
    "darwin": ["libcb2_c.dylib", "libcb2_c.0.dylib"],
    "win32": ["cb2_c.dll", "libcb2_c.dll"],
}


def platform_names() -> list[str]:
    """The file names the shared library carries on this platform."""
    return list(_NAMES.get(sys.platform, ["libcb2_c.so", "libcb2_c.so.0"]))


def package_dirs() -> list[Path]:
    """Every directory of the cb2 package, more than one for an editable install."""
    package = sys.modules.get(__name__.rpartition(".")[0])
    dirs = getattr(package, "__path__", None) or [str(Path(__file__).resolve().parent)]
    return [Path(d) for d in dirs]


def bundled_paths() -> list[str]:
    """The paths a wheel puts the library at: inside the cb2 package."""
    return [str(d / name) for d in package_dirs() for name in platform_names()]


def candidates() -> list[str]:
    """The paths tried in order.

    When CB2_C_LIBRARY is set it is the only candidate, so a wrong
    override fails loudly instead of loading some other copy. Otherwise
    the copy bundled in the package comes first, then whatever
    ctypes.util.find_library finds on the system library path.
    """
    env = os.environ.get(ENV_VAR)
    if env:
        return [env]
    paths = [path for path in bundled_paths() if Path(path).is_file()]
    found = ctypes.util.find_library("cb2_c")
    if found:
        paths.append(found)
    return paths


def _declare(cdll: ctypes.CDLL) -> ctypes.CDLL:
    for name, (restype, argtypes) in _PROTOTYPES.items():
        fn = getattr(cdll, name)
        fn.restype = restype
        fn.argtypes = argtypes
    abi = cdll.cb2_abi_version()
    if abi != ABI_VERSION:
        raise OSError(f"ABI version {abi}, this package needs {ABI_VERSION}")
    return cdll


def load() -> Loaded:
    """Opens the first candidate that loads; raises LibraryNotFound otherwise."""
    tried = []
    for path in candidates():
        try:
            return Loaded(_declare(ctypes.CDLL(path)), path)
        except (OSError, AttributeError) as e:
            tried.append(f"{path} ({e})")
    raise LibraryNotFound(
        "cb2_c shared library not found. Install a cb2 wheel, which bundles it, "
        f"or set {ENV_VAR} to its path, or install it where the system finds it. "
        f"Tried: {'; '.join(tried) or 'nothing'}"
    )


@functools.cache
def loaded() -> Loaded:
    """The library and its path, opened once on first use."""
    return load()


def lib() -> ctypes.CDLL:
    """The loaded library, opened on first use."""
    return loaded().cdll


def take_text(ptr: int | None, length: int | None = None) -> str:
    """Copies a malloc'd text result into a str and frees it."""
    if not ptr:
        return ""
    try:
        raw = ctypes.string_at(ptr) if length is None else ctypes.string_at(ptr, length)
        return raw.decode("utf-8")
    finally:
        lib().cb2_free(ptr)


def take_secret_text(ptr: int | None) -> str:
    """Copies a malloc'd key string into a str, then wipes and frees it."""
    if not ptr:
        return ""
    try:
        return ctypes.string_at(ptr).decode("utf-8")
    finally:
        lib().cb2_free_secret(ptr)


def take_bytes(ptr: int | None, length: int) -> bytes:
    """Copies a malloc'd byte result into bytes and frees it."""
    if not ptr:
        return b""
    try:
        return ctypes.string_at(ptr, length)
    finally:
        lib().cb2_free(ptr)


def optional_text(ptr: int | None) -> str | None:
    """A text result that may be NULL, meaning none."""
    if not ptr:
        return None
    return take_text(ptr)


def as_bytes(value: BytesLike, what: str) -> bytes:
    """UTF-8 encodes str; passes bytes through; refuses anything else."""
    if isinstance(value, str):
        return value.encode("utf-8")
    if isinstance(value, (bytes, bytearray, memoryview)):
        return bytes(value)
    raise TypeError(f"{what} must be str or bytes, not {type(value).__name__}")
