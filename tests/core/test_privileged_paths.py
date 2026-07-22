# ClamUI Privileged Paths Validators Tests
"""
Tests for src.core.privileged_paths.

The validators in this module are the security boundary of the privileged
helper. These tests exercise the allowlist policy, source-file authentication
(uid + mode + staging-root containment), and staging-root verification.
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from src.core import privileged_paths
from src.core.privileged_paths import (
    ALLOWED_DEST_DIRS,
    ALLOWED_DEST_FILES,
    PROTOCOL_VERSION,
    staging_root_for_uid,
    validate_destination,
    validate_source_for_uid,
    verify_staging_root,
)


class TestProtocolVersion:
    """The protocol version is part of the security contract."""

    def test_protocol_version_is_two(self):
        """Helper rejects callers that don't pass --protocol=2."""
        assert PROTOCOL_VERSION == 2


class TestAllowlistShape:
    """The allowlist is the single source of truth and must not regress."""

    def test_allowed_dest_dirs_match_design(self):
        assert Path("/etc/clamav") in ALLOWED_DEST_DIRS
        assert Path("/etc/clamd.d") in ALLOWED_DEST_DIRS
        assert Path("/etc/clamav-unofficial-sigs") in ALLOWED_DEST_DIRS

    def test_allowed_dest_files_contains_freshclam_conf(self):
        assert Path("/etc/freshclam.conf") in ALLOWED_DEST_FILES


class TestStagingRootForUid:
    """staging_root_for_uid() returns the per-user runtime path."""

    def test_returns_per_user_runtime_path(self):
        assert staging_root_for_uid(1000) == Path("/run/user/1000/clamui-staging")

    def test_does_not_create_directory(self, tmp_path, monkeypatch):
        """The function is pure; it must not have I/O side effects."""
        # Implementation hard-codes /run/user/<uid>; just confirm no exception.
        result = staging_root_for_uid(424242)
        assert not result.exists()


class TestValidateDestination:
    """Allowlist + extension policy enforced by validate_destination."""

    def test_accepts_each_allowed_file(self):
        for dest in ALLOWED_DEST_FILES:
            validate_destination(dest)  # must not raise

    def test_accepts_files_directly_under_each_allowed_dir(self):
        for parent in ALLOWED_DEST_DIRS:
            validate_destination(parent / "foo.conf")

    def test_rejects_etc_passwd(self):
        with pytest.raises(ValueError):
            validate_destination(Path("/etc/passwd"))

    def test_rejects_path_traversal(self):
        with pytest.raises(ValueError):
            validate_destination(Path("/etc/clamav/../../passwd"))

    def test_rejects_wrong_extension(self):
        with pytest.raises(ValueError):
            validate_destination(Path("/etc/clamav/foo.txt"))

    def test_rejects_no_extension(self):
        with pytest.raises(ValueError):
            validate_destination(Path("/etc/clamav/foo"))

    def test_rejects_empty_stem_dotconf(self):
        """`.conf` with no name is not a real config file."""
        with pytest.raises(ValueError):
            validate_destination(Path("/etc/clamav/.conf"))

    def test_rejects_subdirectory_of_allowed_dir(self):
        """Allowed dirs accept top-level files only, no nested subdirs."""
        with pytest.raises(ValueError):
            validate_destination(Path("/etc/clamav/sub/foo.conf"))

    def test_rejects_tmp_directory(self):
        with pytest.raises(ValueError):
            validate_destination(Path("/tmp/foo.conf"))

    def test_rejects_home_directory(self):
        with pytest.raises(ValueError):
            validate_destination(Path("/home/user/.config/clamav/clamd.conf"))

    def test_rejects_symlinked_parent(self, tmp_path, monkeypatch):
        """A symlinked parent must not allow escape from the allowlist."""
        attacker_dir = tmp_path / "attacker"
        attacker_dir.mkdir()
        link_parent = tmp_path / "evil_clamav"
        link_parent.symlink_to(attacker_dir)

        # Inject a fake allowlist that includes the symlink's resolved target;
        # the symlink itself must not pretend to be an allowed dir, because
        # validate_destination resolves the parent.
        monkeypatch.setattr(
            privileged_paths,
            "ALLOWED_DEST_DIRS",
            (Path("/etc/clamav"),),
        )
        with pytest.raises(ValueError):
            validate_destination(link_parent / "foo.conf")


def _make_dir(parent: Path, name: str, mode: int) -> Path:
    d = parent / name
    d.mkdir()
    os.chmod(d, mode)
    return d


def _open_nofollow(path: Path, flags: int = os.O_RDONLY) -> int:
    return os.open(str(path), flags | os.O_NOFOLLOW)


class TestValidateSourceForUid:
    """Source authentication for per-pair pkexec apply."""

    def test_accepts_regular_file_under_staging_owned_by_uid(self, tmp_path):
        staging = _make_dir(tmp_path, "staging", 0o700)
        src = staging / "abc.conf"
        src.write_text("LogVerbose yes\n", encoding="utf-8")
        os.chmod(src, 0o600)

        fd = _open_nofollow(src)
        try:
            validate_source_for_uid(fd, src, os.geteuid(), staging)
        finally:
            os.close(fd)

    def test_rejects_wrong_uid(self, tmp_path):
        staging = _make_dir(tmp_path, "staging", 0o700)
        src = staging / "abc.conf"
        src.write_text("x", encoding="utf-8")
        os.chmod(src, 0o600)

        fd = _open_nofollow(src)
        try:
            with pytest.raises(ValueError):
                validate_source_for_uid(fd, src, os.geteuid() + 1, staging)
        finally:
            os.close(fd)

    def test_rejects_group_writable(self, tmp_path):
        staging = _make_dir(tmp_path, "staging", 0o700)
        src = staging / "abc.conf"
        src.write_text("x", encoding="utf-8")
        os.chmod(src, 0o620)

        fd = _open_nofollow(src)
        try:
            with pytest.raises(ValueError):
                validate_source_for_uid(fd, src, os.geteuid(), staging)
        finally:
            os.close(fd)

    def test_rejects_world_writable(self, tmp_path):
        staging = _make_dir(tmp_path, "staging", 0o700)
        src = staging / "abc.conf"
        src.write_text("x", encoding="utf-8")
        os.chmod(src, 0o602)

        fd = _open_nofollow(src)
        try:
            with pytest.raises(ValueError):
                validate_source_for_uid(fd, src, os.geteuid(), staging)
        finally:
            os.close(fd)

    def test_rejects_source_outside_staging_root(self, tmp_path):
        staging = _make_dir(tmp_path, "staging", 0o700)
        outside = tmp_path / "outside"
        outside.mkdir()
        src = outside / "abc.conf"
        src.write_text("x", encoding="utf-8")
        os.chmod(src, 0o600)

        fd = _open_nofollow(src)
        try:
            with pytest.raises(ValueError):
                validate_source_for_uid(fd, src, os.geteuid(), staging)
        finally:
            os.close(fd)

    def test_rejects_fifo(self, tmp_path):
        staging = _make_dir(tmp_path, "staging", 0o700)
        fifo = staging / "abc.conf"
        os.mkfifo(str(fifo), 0o600)

        # O_NONBLOCK is required so opening a fifo for read does not block.
        fd = os.open(str(fifo), os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        try:
            with pytest.raises(ValueError):
                validate_source_for_uid(fd, fifo, os.geteuid(), staging)
        finally:
            os.close(fd)


class TestVerifyStagingRoot:
    """The staging root must be tightly scoped or the helper aborts."""

    def test_accepts_0o700_dir_owned_by_uid(self, tmp_path):
        staging = _make_dir(tmp_path, "staging", 0o700)
        verify_staging_root(staging, os.geteuid())

    def test_accepts_0o500_dir_owned_by_uid(self, tmp_path):
        staging = _make_dir(tmp_path, "staging", 0o500)
        verify_staging_root(staging, os.geteuid())

    def test_rejects_0o755(self, tmp_path):
        staging = _make_dir(tmp_path, "staging", 0o755)
        with pytest.raises(ValueError):
            verify_staging_root(staging, os.geteuid())

    def test_rejects_0o770(self, tmp_path):
        staging = _make_dir(tmp_path, "staging", 0o770)
        with pytest.raises(ValueError):
            verify_staging_root(staging, os.geteuid())

    def test_rejects_wrong_uid(self, tmp_path):
        staging = _make_dir(tmp_path, "staging", 0o700)
        with pytest.raises(ValueError):
            verify_staging_root(staging, os.geteuid() + 1)

    def test_rejects_missing_directory(self, tmp_path):
        with pytest.raises((ValueError, OSError)):
            verify_staging_root(tmp_path / "does_not_exist", os.geteuid())

    def test_rejects_symlink_to_directory(self, tmp_path):
        real_dir = _make_dir(tmp_path, "real", 0o700)
        link = tmp_path / "staging"
        link.symlink_to(real_dir)
        # O_NOFOLLOW must refuse to follow the symlink; either ELOOP from
        # os.open or our own ValueError.
        with pytest.raises((ValueError, OSError)):
            verify_staging_root(link, os.geteuid())
