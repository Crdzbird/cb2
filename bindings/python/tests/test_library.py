from __future__ import annotations

import pickle
import re
from pathlib import Path

import pytest

import cb2
from cb2 import Cb2Error, Code, LibraryNotFound, LocalKey
from cb2 import _lib as native


def test_version_and_feature_flags() -> None:
    assert cb2.version()
    assert isinstance(cb2.has_public(), bool)
    assert isinstance(cb2.has_seal(), bool)
    assert cb2.__version__ == "0.1.0"


@pytest.mark.parametrize(
    ("code", "name"),
    [
        (Code.ARGUMENT, "argument"),
        (0, "ok"),
        (Code.PROOF_REPLAYED, "proof_replayed"),
        (99, "unknown"),
    ],
)
def test_error_names(code: int, name: str) -> None:
    assert cb2.error_name(code) == name


def test_every_code_has_a_name() -> None:
    for code in Code:
        assert cb2.error_name(code) not in ("", "unknown")


def test_library_path_is_the_opened_file() -> None:
    assert Path(cb2.library_path()).name.startswith(("libcb2_c", "cb2_c"))


def test_error_pickles_with_code_and_name() -> None:
    error = Cb2Error(int(Code.EXPIRED), "expired")
    back = pickle.loads(pickle.dumps(error))
    assert (back.code, back.name, str(back)) == (error.code, error.name, "cb2: expired (9)")


def test_key_repr_hides_the_key() -> None:
    key = LocalKey.generate()
    assert repr(key) == "<cb2.LocalKey>"
    assert key.to_paserk() not in repr(key)


def test_env_var_is_the_only_candidate(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(native.ENV_VAR, "/nowhere/libcb2_c.so")
    assert native.candidates() == ["/nowhere/libcb2_c.so"]
    with pytest.raises(LibraryNotFound, match=re.escape("/nowhere/libcb2_c.so")):
        native.load()


def test_without_env_var_bundled_copy_comes_first(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv(native.ENV_VAR, raising=False)
    found = native.candidates()
    bundled = [path for path in native.bundled_paths() if Path(path).is_file()]
    assert found[: len(bundled)] == bundled


def test_library_has_the_abi_this_package_needs() -> None:
    assert native.lib().cb2_abi_version() == native.ABI_VERSION


def test_library_not_found_is_an_os_error() -> None:
    assert issubclass(LibraryNotFound, OSError)
