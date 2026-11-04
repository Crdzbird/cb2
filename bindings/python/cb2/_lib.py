"""Loads the cb2_c shared library and declares every prototype it exports."""

from __future__ import annotations

import ctypes
import ctypes.util
import os
import sys
from ctypes import (
    CFUNCTYPE,
    POINTER,
    c_char_p,
    c_int,
    c_int64,
    c_size_t,
    c_void_p,
)
from pathlib import Path
from typing import List, Optional

from .errors import LibraryNotFound

ENV_VAR = "CB2_C_LIBRARY"

ReplayFn = CFUNCTYPE(c_int, c_void_p, c_char_p, c_size_t)

_PTR_OUT = POINTER(c_void_p)
_LEN_OUT = POINTER(c_size_t)

_KEY_TYPES = ("local_key", "secret_key", "public_key", "recipient_key", "recipient_public_key")

_PROTOTYPES = {
    "cb2_version": (c_char_p, []),
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
    "cb2_local_seal": (c_int, [c_void_p, c_char_p, c_size_t, c_char_p, c_size_t, c_char_p, c_size_t, _PTR_OUT, _LEN_OUT]),
    "cb2_local_open": (c_int, [c_void_p, c_char_p, c_size_t, c_char_p, c_size_t, c_char_p, c_size_t, c_size_t, _PTR_OUT, _LEN_OUT]),
    "cb2_public_sign": (c_int, [c_void_p, c_char_p, c_size_t, c_char_p, c_size_t, c_char_p, c_size_t, _PTR_OUT, _LEN_OUT]),
    "cb2_public_verify": (c_int, [c_void_p, c_char_p, c_size_t, c_char_p, c_size_t, c_char_p, c_size_t, c_size_t, _PTR_OUT, _LEN_OUT]),
    "cb2_token_seal": (c_int, [c_void_p, c_char_p, c_size_t, c_char_p, c_size_t, _PTR_OUT, _LEN_OUT]),
    "cb2_token_sign": (c_int, [c_void_p, c_char_p, c_size_t, c_char_p, c_size_t, _PTR_OUT, _LEN_OUT]),
    "cb2_token_open": (c_int, [c_void_p, c_char_p, c_size_t, c_char_p, c_size_t, c_char_p, c_size_t, ReplayFn, ReplayFn, c_void_p, _PTR_OUT, _LEN_OUT]),
    "cb2_token_verify": (c_int, [c_void_p, c_char_p, c_size_t, c_char_p, c_size_t, c_char_p, c_size_t, ReplayFn, ReplayFn, c_void_p, _PTR_OUT, _LEN_OUT]),
    "cb2_peek_key_id": (c_int, [c_char_p, c_size_t, _PTR_OUT]),
    "cb2_holder_prove": (c_int, [c_void_p, c_char_p, c_size_t, c_char_p, c_size_t, c_char_p, c_size_t, c_char_p, c_size_t, c_char_p, c_size_t, c_int64, c_int64, _PTR_OUT, _LEN_OUT]),
    "cb2_holder_normalize_target": (c_int, [c_char_p, c_size_t, _PTR_OUT]),
    "cb2_wrap": (c_int, [c_void_p, c_void_p, _PTR_OUT]),
    "cb2_unwrap": (c_int, [c_char_p, c_size_t, c_void_p, _PTR_OUT]),
    "cb2_seal": (c_int, [c_void_p, c_void_p, _PTR_OUT]),
    "cb2_unseal": (c_int, [c_char_p, c_size_t, c_void_p, _PTR_OUT]),
}

for _kind in _KEY_TYPES:
    _PROTOTYPES["cb2_%s_from_bytes" % _kind] = (c_int, [c_char_p, c_size_t, _PTR_OUT])
    _PROTOTYPES["cb2_%s_from_paserk" % _kind] = (c_int, [c_char_p, c_size_t, _PTR_OUT])
    _PROTOTYPES["cb2_%s_to_paserk" % _kind] = (c_void_p, [c_void_p])
    _PROTOTYPES["cb2_%s_free" % _kind] = (None, [c_void_p])

for _kind in ("local_key", "secret_key", "public_key"):
    _PROTOTYPES["cb2_%s_key_id" % _kind] = (c_void_p, [c_void_p])
    _PROTOTYPES["cb2_%s_set_key_id" % _kind] = (c_int, [c_void_p, c_char_p, c_size_t])
    _PROTOTYPES["cb2_%s_clear_key_id" % _kind] = (None, [c_void_p])


def platform_names() -> List[str]:
    """The file names the shared library carries on this platform."""
    if sys.platform == "darwin":
        return ["libcb2_c.dylib", "libcb2_c.0.dylib"]
    if sys.platform.startswith("win"):
        return ["cb2_c.dll", "libcb2_c.dll"]
    return ["libcb2_c.so", "libcb2_c.so.0"]


def candidates() -> List[str]:
    """The paths tried in order: the environment, the system, the package."""
    paths = []
    env = os.environ.get(ENV_VAR)
    if env:
        paths.append(env)
    found = ctypes.util.find_library("cb2_c")
    if found:
        paths.append(found)
    here = Path(__file__).resolve().parent
    paths.extend(str(here / name) for name in platform_names())
    return paths


def _declare(lib: ctypes.CDLL) -> ctypes.CDLL:
    for name, (restype, argtypes) in _PROTOTYPES.items():
        fn = getattr(lib, name)
        fn.restype = restype
        fn.argtypes = argtypes
    return lib


def load() -> ctypes.CDLL:
    """Loads the first candidate that opens; raises LibraryNotFound otherwise."""
    tried = []
    for path in candidates():
        try:
            return _declare(ctypes.CDLL(path))
        except OSError as e:
            tried.append("%s (%s)" % (path, e))
    raise LibraryNotFound(
        "cb2_c shared library not found. Set %s to its path, install it where "
        "the system finds it, or copy it next to the cb2 package. Tried: %s"
        % (ENV_VAR, "; ".join(tried) or "nothing")
    )


_lib: Optional[ctypes.CDLL] = None


def lib() -> ctypes.CDLL:
    """The loaded library, opened on first use."""
    global _lib
    if _lib is None:
        _lib = load()
    return _lib


def take_text(ptr: Optional[int], length: Optional[int] = None) -> str:
    """Copies a malloc'd text result into a str and frees it."""
    if not ptr:
        return ""
    try:
        raw = ctypes.string_at(ptr) if length is None else ctypes.string_at(ptr, length)
        return raw.decode("utf-8")
    finally:
        lib().cb2_free(ptr)


def take_secret_text(ptr: Optional[int]) -> str:
    """Copies a malloc'd key string into a str, then wipes and frees it."""
    if not ptr:
        return ""
    try:
        return ctypes.string_at(ptr).decode("utf-8")
    finally:
        lib().cb2_free_secret(ptr)


def take_bytes(ptr: Optional[int], length: int) -> bytes:
    """Copies a malloc'd byte result into bytes and frees it."""
    if not ptr:
        return b""
    try:
        return ctypes.string_at(ptr, length)
    finally:
        lib().cb2_free(ptr)


def optional_text(ptr: Optional[int]) -> Optional[str]:
    """A text result that may be NULL, meaning none."""
    if not ptr:
        return None
    return take_text(ptr)


def as_bytes(value, what: str) -> bytes:
    """UTF-8 encodes str; passes bytes through; refuses anything else."""
    if isinstance(value, str):
        return value.encode("utf-8")
    if isinstance(value, (bytes, bytearray, memoryview)):
        return bytes(value)
    raise TypeError("%s must be str or bytes, not %s" % (what, type(value).__name__))
