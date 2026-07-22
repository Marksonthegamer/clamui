"""
Property-based tests for src/core/scheduler._validate_target_paths.

Focuses on injection safety: the scheduler builds cron/systemd unit content
from target paths, so any path containing newlines, carriage returns, or
null bytes must be rejected. Accepted paths must additionally survive a
shlex quote/split round-trip to prove they compose safely into shell
command strings.
"""

from __future__ import annotations

import shlex
import string

import pytest
from hypothesis import assume, given
from hypothesis import strategies as st

from src.core.scheduler import _validate_target_paths
from tests.property.strategies import injection_path, safe_path

pytestmark = pytest.mark.property


@given(st.text(max_size=30), st.text(max_size=30), st.sampled_from(["\n", "\r"]))
def test_newline_is_always_rejected(prefix: str, suffix: str, nl: str) -> None:
    """Any path containing \\n or \\r is rejected with a newline error."""
    target = f"{prefix}{nl}{suffix}"
    result = _validate_target_paths([target])
    assert result is not None
    assert "newline" in result.lower()


@given(st.text(max_size=30), st.text(max_size=30))
def test_null_byte_is_always_rejected(prefix: str, suffix: str) -> None:
    """Any path containing \\x00 is rejected with a null-bytes error."""
    # Avoid also containing a newline so we deterministically hit the null check.
    assume("\n" not in prefix and "\n" not in suffix)
    assume("\r" not in prefix and "\r" not in suffix)
    target = f"{prefix}\x00{suffix}"
    result = _validate_target_paths([target])
    assert result is not None
    assert "null" in result.lower()


@given(safe_path())
def test_safe_printable_path_accepted(path: str) -> None:
    """Paths from the safe alphabet (no \\n/\\r/\\x00) are accepted."""
    assert _validate_target_paths([path]) is None


@given(st.lists(safe_path(), min_size=0, max_size=5))
def test_list_of_safe_paths_accepted(paths: list[str]) -> None:
    assert _validate_target_paths(paths) is None


def test_empty_list_accepted() -> None:
    assert _validate_target_paths([]) is None


@given(safe_path(), injection_path())
def test_first_bad_wins(safe: str, bad: str) -> None:
    """
    A list containing a safe path followed by a bad path rejects iff
    validating the bad path alone rejects.
    """
    bad_result = _validate_target_paths([bad])
    combined_result = _validate_target_paths([safe, bad])
    if bad_result is None:
        assert combined_result is None
    else:
        assert combined_result is not None


@given(st.lists(injection_path(), min_size=1, max_size=4))
def test_any_injection_path_fails_if_individually_fails(paths: list[str]) -> None:
    """Composite rejection ↔ at least one individual rejection."""
    combined = _validate_target_paths(paths)
    individuals = [_validate_target_paths([p]) for p in paths]
    any_bad = any(r is not None for r in individuals)
    if any_bad:
        assert combined is not None
    else:
        assert combined is None


@given(safe_path())
def test_accepted_path_shlex_roundtrips(path: str) -> None:
    """
    Every accepted path survives shlex.quote → shlex.split as a single token.
    This is the key property that guarantees injection safety of downstream
    cron/systemd command construction.
    """
    assert _validate_target_paths([path]) is None
    quoted = shlex.quote(path)
    tokens = shlex.split(quoted)
    assert tokens == [path]


@given(st.text(alphabet=string.printable, max_size=60))
def test_printable_without_newlines_or_nulls(text: str) -> None:
    """
    Any string from string.printable that lacks \\n, \\r, \\x00 passes
    validation. (string.printable includes whitespace, so filter.)
    """
    if any(c in text for c in "\n\r\x00"):
        return
    assert _validate_target_paths([text]) is None


@given(st.text(max_size=50))
def test_validate_target_paths_is_total(text: str) -> None:
    """Never raises for any string input."""
    result = _validate_target_paths([text])
    assert result is None or isinstance(result, str)


@given(st.lists(st.text(max_size=20), max_size=6))
def test_validate_target_paths_return_shape(paths: list[str]) -> None:
    result = _validate_target_paths(paths)
    assert result is None or isinstance(result, str)
