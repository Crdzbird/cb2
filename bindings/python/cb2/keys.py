"""Key handles: thin owners of the opaque pointers the C ABI hands out."""

from __future__ import annotations

import ctypes
from ctypes import c_void_p
from typing import Optional, Type, TypeVar

from ._lib import as_bytes, lib, optional_text, take_secret_text, take_text
from .errors import Cb2Error, Code, check

K = TypeVar("K", bound="_Key")


class _Key:
    """A handle released by the matching cb2_*_free when collected."""

    _kind = ""
    _secret_paserk = False

    def __init__(self, ptr: int):
        if not ptr:
            raise Cb2Error(Code.INTERNAL, "internal")
        self._ptr = ptr
        self._free = getattr(lib(), "cb2_%s_free" % self._kind)

    def __del__(self):
        ptr = getattr(self, "_ptr", None)
        if ptr:
            self._ptr = None
            self._free(ptr)

    @property
    def handle(self) -> int:
        """The raw pointer for the duration of a call."""
        if not self._ptr:
            raise Cb2Error(Code.ARGUMENT, "argument")
        return self._ptr

    @classmethod
    def _call(cls, name: str):
        return getattr(lib(), "cb2_%s_%s" % (cls._kind, name))

    @classmethod
    def _create(cls: Type[K], name: str, *args) -> K:
        out = c_void_p()
        check(cls._call(name)(*args, ctypes.byref(out)))
        return cls(out.value)

    @classmethod
    def from_bytes(cls: Type[K], data: bytes) -> K:
        """A key from its raw bytes."""
        raw = bytes(data)
        return cls._create("from_bytes", raw, len(raw))

    @classmethod
    def from_paserk(cls: Type[K], text: str) -> K:
        """A key from its PASERK text."""
        raw = as_bytes(text, "paserk")
        return cls._create("from_paserk", raw, len(raw))

    def to_paserk(self) -> str:
        """The PASERK text of the key."""
        ptr = self._call("to_paserk")(self.handle)
        if not ptr:
            raise Cb2Error(Code.UNAVAILABLE, "unavailable")
        if self._secret_paserk:
            return take_secret_text(ptr)
        return take_text(ptr)

    def paserk_id(self) -> str:
        """The PASERK id of the key."""
        ptr = self._call("paserk_id")(self.handle)
        if not ptr:
            raise Cb2Error(Code.UNAVAILABLE, "unavailable")
        return take_text(ptr)


class _NamedKey(_Key):
    """A key that can carry a key id, bound into the footer of claims tokens."""

    @property
    def key_id(self) -> Optional[str]:
        """The key id, or None when the key has none."""
        return optional_text(self._call("key_id")(self.handle))

    @key_id.setter
    def key_id(self, value: Optional[str]) -> None:
        if value is None:
            self.clear_key_id()
            return
        raw = as_bytes(value, "key_id")
        check(self._call("set_key_id")(self.handle, raw, len(raw)))

    def clear_key_id(self) -> None:
        """Removes the key id."""
        self._call("clear_key_id")(self.handle)


class _GeneratedKey:
    """Mixin for the key kinds the library generates."""

    @classmethod
    def generate(cls):
        """A fresh random key."""
        return cls._create("generate")


class LocalKey(_GeneratedKey, _NamedKey):
    """A symmetric key for cb2.local tokens (kcb2.local)."""

    _kind = "local_key"
    _secret_paserk = True


class PublicKey(_NamedKey):
    """The public half of a signing pair (kcb2.public)."""

    _kind = "public_key"


class SecretKey(_GeneratedKey, _NamedKey):
    """A signing pair for cb2.public tokens (kcb2.secret)."""

    _kind = "secret_key"
    _secret_paserk = True

    def public_key(self) -> PublicKey:
        """The public half."""
        out = c_void_p()
        check(lib().cb2_secret_key_public_key(self.handle, ctypes.byref(out)))
        return PublicKey(out.value)

    def paserk_id(self) -> str:
        """The PASERK id of the public half, which identifies the pair."""
        return self.public_key().paserk_id()


class RecipientPublicKey(_Key):
    """The public half of a recipient pair for kcb2.seal (kcb2.recipient)."""

    _kind = "recipient_public_key"


class RecipientKey(_GeneratedKey, _Key):
    """A recipient pair for kcb2.seal (kcb2.recipient-secret)."""

    _kind = "recipient_key"
    _secret_paserk = True

    def public_key(self) -> RecipientPublicKey:
        """The public half."""
        out = c_void_p()
        check(lib().cb2_recipient_key_public_key(self.handle, ctypes.byref(out)))
        return RecipientPublicKey(out.value)
