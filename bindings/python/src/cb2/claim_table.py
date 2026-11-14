"""Claim tables for compact claims tokens."""

from __future__ import annotations

import ctypes
import json
from collections.abc import Callable, Iterable
from ctypes import c_void_p

from ._lib import lib, take_bytes
from .errors import Cb2Error, Code, check


class ClaimTable:
    """An ordered list of strings an issuer and its verifiers share, typically the issuer's name and its audiences.

    Under a table, an iss or aud equal to an entry travels as its index,
    so the compact token is shorter. The table is never sent: its digest
    is bound into the token, which opens only under the same table, in
    the same order; under another table or none it is INVALID. A table
    has 1 to 256 entries, each non-empty, distinct and an identifier;
    anything else is refused with ARGUMENT. It is immutable and may be
    shared between threads.
    """

    DIGEST_BYTES = 32
    """The size of the table's digest."""

    def __init__(self, entries: Iterable[str]) -> None:
        if isinstance(entries, (str, bytes, bytearray, memoryview)):
            raise TypeError("entries must be an iterable of str, not a single string")
        listed = tuple(entries)
        text = json.dumps(list(listed), ensure_ascii=False).encode("utf-8")
        out = c_void_p()
        check(lib().cb2_claim_table_from_json(text, len(text), ctypes.byref(out)))
        if not out.value:
            raise Cb2Error(Code.INTERNAL, "internal")
        self._ptr: int | None = out.value
        self._free: Callable[[int], None] = lib().cb2_claim_table_free
        self._entries = listed

    def __del__(self) -> None:
        ptr = getattr(self, "_ptr", None)
        if ptr:
            self._ptr = None
            self._free(ptr)

    def __repr__(self) -> str:
        return f"<cb2.ClaimTable {len(self._entries)} entries>"

    @property
    def entries(self) -> tuple[str, ...]:
        """The entries, in order."""
        return self._entries

    @property
    def handle(self) -> int:
        """The raw pointer for the duration of a call."""
        if not self._ptr:
            raise Cb2Error(Code.ARGUMENT, "argument")
        return self._ptr

    def digest(self) -> bytes:
        """The DIGEST_BYTES digest of the table, so two parties can compare their tables."""
        out = c_void_p()
        check(lib().cb2_claim_table_digest(self.handle, ctypes.byref(out)))
        return take_bytes(out.value, self.DIGEST_BYTES)
