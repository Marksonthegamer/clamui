"""
Property-based tests for src/core/path_validation.py.

Covers the pure-input behaviour of validate_path, validate_dropped_files,
and format_scan_path. Filesystem interactions are exercised only with
controlled tmp_path fixtures.
"""

from __future__ import annotations

import string
from pathlib import Path

import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from src.core.path_validation import (
    check_symlink_safety,
    format_scan_path,
    validate_dropped_files,
    validate_path,
)

pytestmark = pytest.mark.property


@given(st.text(alphabet=" \t\r\n", max_size=10))
def test_validate_path_rejects_empty_and_whitespace(text: str) -> None:
    ok, err = validate_path(text)
    assert ok is False
    assert err == "No path specified"


@given(st.text(min_size=1, max_size=100))
def test_validate_path_is_deterministic(text: str) -> None:
    assert validate_path(text) == validate_path(text)


@given(st.text(min_size=1, max_size=100))
def test_validate_path_returns_tuple(text: str) -> None:
    result = validate_path(text)
    assert isinstance(result, tuple)
    assert len(result) == 2
    ok, err = result
    assert isinstance(ok, bool)
    assert err is None or isinstance(err, str)


@given(st.text(min_size=1, max_size=100))
def test_validate_path_success_implies_no_error(text: str) -> None:
    ok, err = validate_path(text)
    if ok:
        assert err is None


def test_validate_dropped_files_empty_list() -> None:
    valid, errors = validate_dropped_files([])
    assert valid == []
    assert len(errors) == 1
    assert "No files" in errors[0]


@given(st.integers(min_value=1, max_value=5))
def test_validate_dropped_files_all_none(count: int) -> None:
    """None entries always produce 'Remote files' errors, no valid paths."""
    paths: list[str | None] = [None] * count
    valid, errors = validate_dropped_files(paths)
    assert valid == []
    assert len(errors) == count
    for err in errors:
        assert "Remote" in err


@given(
    st.lists(
        st.one_of(
            st.none(),
            st.text(
                alphabet=string.ascii_letters + string.digits + "/._-",
                min_size=1,
                max_size=30,
            ),
        ),
        min_size=1,
        max_size=5,
    )
)
def test_validate_dropped_files_none_count_equals_remote_errors(
    paths: list[str | None],
) -> None:
    """The number of None entries matches the count of 'Remote files' errors."""
    none_count = sum(1 for p in paths if p is None)
    _valid, errors = validate_dropped_files(paths)
    remote_errors = [e for e in errors if "Remote" in e]
    assert len(remote_errors) == none_count


@given(st.one_of(st.none(), st.text(max_size=200)))
def test_format_scan_path_is_total(text: str | None) -> None:
    """format_scan_path never raises for empty or arbitrary string input."""
    result = format_scan_path(text or "")
    assert isinstance(result, str)


def test_format_scan_path_empty() -> None:
    assert format_scan_path("") == "No path selected"


@given(st.text(min_size=1, max_size=100))
def test_format_scan_path_returns_nonempty(text: str) -> None:
    result = format_scan_path(text)
    assert isinstance(result, str)
    assert len(result) > 0


@settings(suppress_health_check=[HealthCheck.function_scoped_fixture])
@given(
    st.text(
        alphabet=string.ascii_letters + string.digits + "_-",
        min_size=1,
        max_size=12,
    )
)
def test_check_symlink_safety_regular_file_is_safe(tmp_path: Path, filename: str) -> None:
    """A regular file under tmp_path that exists is considered safe."""
    target = tmp_path / filename
    target.write_text("data", encoding="utf-8")
    ok, msg = check_symlink_safety(target)
    assert ok is True
    assert msg is None or isinstance(msg, str)


@settings(suppress_health_check=[HealthCheck.function_scoped_fixture])
@given(
    st.text(
        alphabet=string.ascii_letters + string.digits + "_-",
        min_size=1,
        max_size=12,
    )
)
def test_check_symlink_safety_returns_bool_and_optional_str(tmp_path: Path, filename: str) -> None:
    """Return shape invariant: always (bool, str | None)."""
    target = tmp_path / filename
    target.write_text("data", encoding="utf-8")
    ok, msg = check_symlink_safety(target)
    assert isinstance(ok, bool)
    assert msg is None or isinstance(msg, str)


def test_validate_path_nonexistent_is_invalid(tmp_path: Path) -> None:
    """A path under tmp_path that does not exist is reported invalid."""
    missing = tmp_path / "definitely-not-here-xyz"
    ok, err = validate_path(str(missing))
    assert ok is False
    assert err is not None
    assert "exist" in err.lower() or "permission" in err.lower()
