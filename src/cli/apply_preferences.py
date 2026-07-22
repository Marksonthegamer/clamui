# ClamUI Privileged Preferences Apply Helper
"""
Helper command for applying configuration files with elevated privileges.

This CLI is intended to be invoked via ``pkexec`` by the GUI layer.  It is
deliberately small, has no GTK dependency, and treats every input as
adversarial.  See ``src/core/privileged_paths.py`` for the validators that
form the actual security boundary; this module is the wiring around them.

Protocol (version 2):

    PKEXEC_UID=<uid>  pkexec  clamui-apply-preferences  --protocol=2 \\
        <staged-src-1> <dest-1>  [<staged-src-2> <dest-2> ...]

The helper:

1. Reads ``PKEXEC_UID`` from the environment; refuses if missing, ``0``,
   or non-numeric (exit 3).  This pins source-file authentication to the
   user who actually authorised the elevation, not to the running root
   process.
2. Requires ``--protocol=2`` as the first positional argument so an
   outdated caller paired with the hardened helper fails closed (exit 4)
   instead of being interpreted as ``src dest src dest ...``.
3. Resolves the per-user staging root, opens it ``O_NOFOLLOW`` /
   ``O_DIRECTORY``, and verifies it is owned by the calling UID with
   mode ``0o700`` (or stricter).
4. For each ``(src, dst)`` pair:

   - Opens ``src`` with ``O_RDONLY | O_NOFOLLOW | O_NONBLOCK`` (refuses
     symlinks atomically, refuses to block on FIFOs).
   - ``fstat``s the descriptor and confirms regular-file, owning UID,
     no group/world write, resolved path under the staging root.
   - Validates the destination against the allowlist (``.conf`` extension,
     no traversal, parent must be one of the allowed dirs after symlink
     resolution).
   - Atomically installs via ``mkstemp`` in the destination directory,
     ``copyfileobj`` from the validated FD, ``fsync``, ``chmod 0o644``,
     ``os.replace`` onto the destination.  On any error the temp file is
     unlinked.

5. Restarts any active ClamAV systemd units affected by the writes.
"""

from __future__ import annotations

import logging
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

from ..core.privileged_paths import (
    PROTOCOL_VERSION,
    staging_root_for_uid,
    validate_destination,
    validate_source_for_uid,
    verify_staging_root,
)

logger = logging.getLogger(__name__)


_FRESHCLAM_UNITS: tuple[str, ...] = (
    "clamav-freshclam.service",
    "freshclam.service",
)

_CLAMD_UNITS: tuple[str, ...] = (
    "clamav-daemon.service",
    "clamd.service",
    "clamd@scan.service",
    "clamav-clamonacc.service",
)


# --- Exit codes -----------------------------------------------------------
# 0  success
# 1  generic error (validation failure, IO error, restart failure)
# 2  argument parsing error (odd number of pairs, no pairs)
# 3  PKEXEC_UID missing/zero/non-numeric
# 4  protocol mismatch (caller did not pass --protocol=2 first)
EXIT_OK = 0
EXIT_GENERIC_ERROR = 1
EXIT_BAD_ARGS = 2
EXIT_BAD_PKEXEC_UID = 3
EXIT_BAD_PROTOCOL = 4


def _parse_path_pairs(args: list[str]) -> list[tuple[Path, Path]]:
    """
    Parse remaining arguments into ``(source, destination)`` path pairs.

    Args:
        args: Flat list of alternating source and destination paths
            (after the ``--protocol=2`` token has been consumed).

    Returns:
        List of ``(source, destination)`` ``Path`` tuples.

    Raises:
        ValueError: If args are empty or not provided as pairs.
    """
    if not args:
        raise ValueError("No staged configuration files were provided.")
    if len(args) % 2 != 0:
        raise ValueError("Invalid arguments: expected source/destination path pairs.")

    pairs: list[tuple[Path, Path]] = []
    for idx in range(0, len(args), 2):
        pairs.append((Path(args[idx]), Path(args[idx + 1])))
    return pairs


def _parse_pkexec_uid() -> int | None:
    """Return ``PKEXEC_UID`` as an int, or ``None`` if missing/zero/invalid."""
    raw = os.environ.get("PKEXEC_UID")
    if raw is None:
        return None
    try:
        uid = int(raw)
    except ValueError:
        return None
    if uid <= 0:
        return None
    return uid


def _resolve_staging_root(uid: int) -> Path:
    """Indirection seam so tests can redirect the staging root under tmp_path."""
    return staging_root_for_uid(uid)


def _atomic_install(source_fd: int, destination: Path) -> None:
    """
    Atomically install ``source_fd``'s content into ``destination`` (mode 0o644).

    The temp file is created in the *destination* directory so ``os.replace``
    is a same-filesystem rename and therefore atomic.  Any failure unlinks
    the temp file before re-raising; the destination is never left in a
    partially-written state.

    Args:
        source_fd: Validated, ``O_NOFOLLOW``-opened source descriptor.  This
            function takes ownership and closes it via ``os.fdopen``.
        destination: Final destination path.  The parent must already exist.
    """
    dst_dir = destination.parent
    dst_dir.mkdir(parents=True, exist_ok=True)

    tmp_fd, tmp_name = tempfile.mkstemp(
        dir=str(dst_dir),
        prefix=f".{destination.name}.",
        suffix=".tmp",
    )
    try:
        with (
            os.fdopen(source_fd, "rb", closefd=True) as src_f,
            os.fdopen(tmp_fd, "wb", closefd=True) as tmp_f,
        ):
            shutil.copyfileobj(src_f, tmp_f)
            tmp_f.flush()
            os.fsync(tmp_f.fileno())
        os.chmod(tmp_name, 0o644)
        os.replace(tmp_name, destination)
    except BaseException:
        # If anything went wrong, make sure no half-written file lingers.
        try:
            os.unlink(tmp_name)
        except FileNotFoundError:
            pass
        raise


def _apply_pair(
    source: Path,
    destination: Path,
    expected_uid: int,
    staging_root: Path,
) -> None:
    """
    Validate one ``(source, destination)`` pair and install it atomically.

    Args:
        source: Staged file path (must live under ``staging_root``).
        destination: Final destination path (must satisfy the allowlist).
        expected_uid: UID that must own ``source`` (typically ``PKEXEC_UID``).
        staging_root: Per-invocation staging directory.

    Raises:
        ValueError: On any validation failure.
        OSError: From ``os.open`` (e.g. ``ELOOP`` for a symlink source).
    """
    # Validate destination FIRST so a bad destination short-circuits before
    # we even open the source file.  Fail-fast ordering also matters for
    # multi-pair atomicity: see ``main`` where every pair is validated
    # before any pair is installed.
    validate_destination(destination)

    src_fd = os.open(
        str(source),
        os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK,
    )
    try:
        validate_source_for_uid(src_fd, source, expected_uid, staging_root)
    except BaseException:
        os.close(src_fd)
        raise

    # _atomic_install takes ownership of src_fd and closes it.
    _atomic_install(src_fd, destination)


def _restart_units_for_destinations(destinations: list[Path]) -> None:
    """
    Restart active ClamAV services affected by the written config files.

    Only active services are restarted so distro-specific or disabled units
    are skipped without failing the save operation.

    Args:
        destinations: Final config destinations that were updated.
    """
    if shutil.which("systemctl") is None:
        return

    units_to_restart: list[str] = []
    for destination in destinations:
        if destination.name == "freshclam.conf":
            units_to_restart.extend(_FRESHCLAM_UNITS)
        elif destination.name == "clamd.conf" or destination.parent == Path("/etc/clamd.d"):
            units_to_restart.extend(_CLAMD_UNITS)

    seen_units: set[str] = set()
    for unit in units_to_restart:
        if unit in seen_units:
            continue
        seen_units.add(unit)

        active_result = subprocess.run(
            ["systemctl", "is-active", "--quiet", unit],
            capture_output=True,
            text=True,
        )
        if active_result.returncode != 0:
            continue

        restart_result = subprocess.run(
            ["systemctl", "restart", unit],
            capture_output=True,
            text=True,
        )
        if restart_result.returncode != 0:
            error = (
                restart_result.stderr.strip() or restart_result.stdout.strip() or "unknown error"
            )
            raise RuntimeError(f"Failed to restart {unit}: {error}")


def main(argv: list[str] | None = None) -> int:
    """
    Entry point for the privileged preferences apply helper.

    Args:
        argv: Optional argument list (defaults to ``sys.argv[1:]``).

    Returns:
        Exit status code.  See module docstring for the meaning of each code.
    """
    args = list(sys.argv[1:] if argv is None else argv)

    uid = _parse_pkexec_uid()
    if uid is None:
        print(
            "Error: PKEXEC_UID is missing or invalid; refusing to run.",
            file=sys.stderr,
        )
        return EXIT_BAD_PKEXEC_UID

    expected_protocol = f"--protocol={PROTOCOL_VERSION}"
    if not args or args[0] != expected_protocol:
        print(
            f"Error: missing or wrong protocol token; expected {expected_protocol} as the "
            "first argument.",
            file=sys.stderr,
        )
        return EXIT_BAD_PROTOCOL
    args = args[1:]

    try:
        pairs = _parse_path_pairs(args)
    except ValueError as error:
        print(f"Error: {error}", file=sys.stderr)
        return EXIT_BAD_ARGS

    staging_root = _resolve_staging_root(uid)
    try:
        verify_staging_root(staging_root, uid)
    except (ValueError, OSError) as error:
        print(f"Error: invalid staging root: {error}", file=sys.stderr)
        return EXIT_GENERIC_ERROR

    # Two-phase: validate every pair before installing any pair.  If pair #2
    # has a bad destination we must NOT have installed pair #1 yet.
    try:
        for _source, destination in pairs:
            validate_destination(destination)
    except ValueError as error:
        print(f"Error: {error}", file=sys.stderr)
        return EXIT_GENERIC_ERROR

    try:
        destinations: list[Path] = []
        for source, destination in pairs:
            _apply_pair(source, destination, uid, staging_root)
            destinations.append(destination)
        _restart_units_for_destinations(destinations)
    except Exception as error:
        print(f"Error: {error}", file=sys.stderr)
        return EXIT_GENERIC_ERROR

    return EXIT_OK


if __name__ == "__main__":
    raise SystemExit(main())
