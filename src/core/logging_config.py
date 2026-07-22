# ClamUI Logging Configuration Module
"""
Centralized logging configuration for ClamUI.

This module provides a configurable logging system with:
- Privacy-aware formatting that replaces home directory paths with ~
- Rotating file handlers to manage disk space
- Thread-safe runtime reconfiguration
- Log export and management utilities

Logging should be configured early in application startup, before
other modules that use logging are imported.
"""

import contextlib
import logging
import os
import tempfile
import threading
import zipfile
from datetime import datetime
from logging.handlers import RotatingFileHandler
from pathlib import Path

from .sanitize import sanitize_path_for_logging

# Default log directory follows XDG specification
DEFAULT_LOG_DIR = (
    Path(os.environ.get("XDG_DATA_HOME", os.path.expanduser("~/.local/share"))) / "clamui" / "debug"
)

# Default log settings
DEFAULT_LOG_LEVEL = "WARNING"
DEFAULT_MAX_BYTES = 5 * 1024 * 1024  # 5 MB
DEFAULT_BACKUP_COUNT = 3  # 3 backup files = 20 MB max total

# Log format with timestamp, level, module, and message
LOG_FORMAT = "%(asctime)s - %(levelname)s - %(name)s - %(message)s"
DATE_FORMAT = "%Y-%m-%d %H:%M:%S"
DEBUG_LOG_PRIVACY_VERSION = 1
PRIVACY_STATE_FILENAME = ".debug-log-privacy-version"


class PrivacyFormatter(logging.Formatter):
    """
    Custom log formatter that redacts file-identifying values for privacy.

    Runtime debug logs must never persist scan targets, file paths, hashes,
    or report URLs. This formatter rewrites those values before they reach disk.
    """

    def format(self, record: logging.LogRecord) -> str:
        """
        Format the log record with privacy-aware path sanitization.

        Args:
            record: The log record to format

        Returns:
            Formatted log string with sanitized paths
        """
        # Format the message first
        formatted = super().format(record)

        # Redact sensitive values in the formatted message
        return sanitize_path_for_logging(formatted)


class LoggingConfig:
    """
    Singleton manager for ClamUI logging configuration.

    Provides thread-safe methods for configuring logging, changing
    log levels at runtime, and managing log files (export, clear).
    """

    _instance: "LoggingConfig | None" = None
    _lock = threading.Lock()

    def __new__(cls) -> "LoggingConfig":
        """Ensure only one instance exists (singleton pattern)."""
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    cls._instance = super().__new__(cls)
                    cls._instance._initialized = False
        return cls._instance

    def __init__(self):
        """Initialize the logging configuration (only runs once)."""
        if self._initialized:
            return

        self._file_handler: RotatingFileHandler | None = None
        self._log_dir: Path = DEFAULT_LOG_DIR
        self._log_file: Path | None = None
        self._sanitization_thread: threading.Thread | None = None
        self._config_lock = threading.Lock()
        self._initialized = True

    def configure(
        self,
        log_dir: Path | str | None = None,
        log_level: str = DEFAULT_LOG_LEVEL,
        max_bytes: int = DEFAULT_MAX_BYTES,
        backup_count: int = DEFAULT_BACKUP_COUNT,
    ) -> bool:
        """
        Configure the logging system.

        Sets up a rotating file handler with privacy-aware formatting.
        Should be called early in application startup.

        Args:
            log_dir: Directory for log files (default: ~/.local/share/clamui/debug/)
            log_level: Logging level (DEBUG, INFO, WARNING, ERROR)
            max_bytes: Maximum size per log file in bytes
            backup_count: Number of backup files to keep

        Returns:
            True if configuration succeeded, False otherwise
        """
        with self._config_lock:
            try:
                root_logger = logging.getLogger("src")

                # Remove existing handler before rewriting log files.
                if self._file_handler is not None:
                    root_logger.removeHandler(self._file_handler)
                    self._file_handler.close()
                    self._file_handler = None

                # Set up log directory
                if log_dir is not None:
                    self._log_dir = Path(log_dir)
                else:
                    self._log_dir = DEFAULT_LOG_DIR

                # Create log directory with restricted permissions
                self._log_dir.mkdir(parents=True, exist_ok=True)
                # Secure the directory (owner only)
                self._log_dir.chmod(0o700)

                # Set up log file path
                self._log_file = self._log_dir / "clamui.log"

                # Only perform a full startup migration once. After legacy logs
                # have been scrubbed, future sessions append to the sanitized
                # active log directly and skip any background work.
                if not self._has_completed_privacy_migration_unlocked():
                    self._relocate_active_log_for_background_sanitization_locked()

                # Create rotating file handler
                self._file_handler = RotatingFileHandler(
                    self._log_file,
                    maxBytes=max_bytes,
                    backupCount=backup_count,
                    encoding="utf-8",
                )

                # Set file permissions (owner read/write only)
                if self._log_file.exists():
                    self._log_file.chmod(0o600)

                # Configure formatter with privacy sanitization
                formatter = PrivacyFormatter(LOG_FORMAT, DATE_FORMAT)
                self._file_handler.setFormatter(formatter)

                # Set log level
                level = getattr(logging, log_level.upper(), logging.WARNING)
                self._file_handler.setLevel(level)

                # Configure the root logger for "src" package
                root_logger.setLevel(level)
                root_logger.addHandler(self._file_handler)

                # Log successful initialization
                root_logger.info(
                    "Logging configured: level=%s, max_size=%d bytes, backups=%d",
                    log_level,
                    max_bytes,
                    backup_count,
                )

                # Redact historical debug logs off the startup critical path.
                self._schedule_existing_log_sanitization_locked()

                return True

            except (OSError, PermissionError) as e:
                # Log to stderr if file logging fails
                import sys

                print(f"Failed to configure logging: {e}", file=sys.stderr)
                return False

    def _relocate_active_log_for_background_sanitization_locked(self) -> None:
        """Rename the previous active log so a new session can start immediately."""
        if self._log_file is None or not self._log_file.exists():
            return

        try:
            if self._log_file.stat().st_size == 0:
                return
        except OSError:
            return

        timestamp = datetime.now().strftime("%Y%m%d%H%M%S%f")
        archived_log = self._log_dir / f"clamui.log.pending-redaction-{timestamp}"
        try:
            self._log_file.replace(archived_log)
            archived_log.chmod(0o600)
        except OSError:
            # If the rename fails, leave the file in place and let later cleanup
            # sanitize it when possible.
            return

    def _get_privacy_state_file_unlocked(self) -> Path:
        """Return the marker file that tracks debug-log privacy migration state."""
        return self._log_dir / PRIVACY_STATE_FILENAME

    def _read_privacy_state_version_unlocked(self) -> int:
        """Read the stored privacy migration version from disk."""
        state_file = self._get_privacy_state_file_unlocked()
        try:
            return int(state_file.read_text(encoding="utf-8").strip() or "0")
        except (OSError, ValueError):
            return 0

    def _has_completed_privacy_migration_unlocked(self) -> bool:
        """Return True when legacy debug logs were already scrubbed."""
        return self._read_privacy_state_version_unlocked() >= DEBUG_LOG_PRIVACY_VERSION

    def _mark_privacy_migration_complete_unlocked(self) -> None:
        """Persist the current debug-log privacy migration version."""
        fd, temp_path = tempfile.mkstemp(
            prefix="debug_privacy_",
            dir=self._log_dir,
        )
        try:
            try:
                f = os.fdopen(fd, "w", encoding="utf-8")
            except Exception:
                with contextlib.suppress(OSError):
                    os.close(fd)
                raise

            with f:
                f.write(str(DEBUG_LOG_PRIVACY_VERSION))

            state_file = self._get_privacy_state_file_unlocked()
            Path(temp_path).replace(state_file)
            state_file.chmod(0o600)
        except Exception:
            with contextlib.suppress(OSError):
                Path(temp_path).unlink(missing_ok=True)

    def _clear_privacy_migration_state_unlocked(self) -> None:
        """Delete the debug-log privacy migration marker."""
        with contextlib.suppress(OSError):
            self._get_privacy_state_file_unlocked().unlink()

    @staticmethod
    def _is_pending_redaction_file(log_file: Path) -> bool:
        """Return True when a log file still needs pending-redaction finalization."""
        return ".pending-redaction-" in log_file.name

    def _collect_sanitization_targets_unlocked(self, *, force_full: bool = False) -> list[Path]:
        """Collect log files that still require privacy sanitization."""
        log_files = self._get_log_files_unlocked()

        if force_full or not self._has_completed_privacy_migration_unlocked():
            return [
                log_file
                for log_file in log_files
                if self._log_file is None or log_file != self._log_file
            ]

        return [log_file for log_file in log_files if self._is_pending_redaction_file(log_file)]

    def _finalize_sanitized_log_file_unlocked(self, log_file: Path) -> None:
        """Rename pending-redaction files once they have been processed."""
        if not self._is_pending_redaction_file(log_file):
            return

        finalized_name = log_file.name.replace("pending-redaction", "archived", 1)
        finalized_path = log_file.with_name(finalized_name)
        if finalized_path.exists():
            return

        with contextlib.suppress(OSError):
            log_file.replace(finalized_path)
            finalized_path.chmod(0o600)

    def _schedule_existing_log_sanitization_locked(self) -> None:
        """Start background sanitization for older debug log files if needed."""
        if not self._collect_sanitization_targets_unlocked():
            if not self._has_completed_privacy_migration_unlocked():
                self._mark_privacy_migration_complete_unlocked()
            return

        if self._sanitization_thread is not None and self._sanitization_thread.is_alive():
            return

        thread = threading.Thread(
            target=self._sanitize_existing_log_files_background,
            name="clamui-log-sanitizer",
            daemon=True,
        )
        self._sanitization_thread = thread
        thread.start()

    def _sanitize_existing_log_files_background(self) -> None:
        """Run debug log sanitization outside the startup critical path."""
        with self._config_lock:
            self._sanitize_existing_log_files_locked()

    def _sanitize_existing_log_files_locked(self, *, force_full: bool = False) -> None:
        """Rewrite older debug log files with privacy redaction applied."""
        targets = self._collect_sanitization_targets_unlocked(force_full=force_full)
        if not targets:
            if force_full or not self._has_completed_privacy_migration_unlocked():
                self._mark_privacy_migration_complete_unlocked()
            return

        for log_file in targets:
            try:
                content = log_file.read_text(encoding="utf-8")
                sanitized = sanitize_path_for_logging(content)
                if sanitized != content:
                    log_file.write_text(sanitized, encoding="utf-8")
                    log_file.chmod(0o600)
                self._finalize_sanitized_log_file_unlocked(log_file)
            except OSError:
                continue

        if force_full or not self._has_completed_privacy_migration_unlocked():
            self._mark_privacy_migration_complete_unlocked()

    def set_log_level(self, level: str) -> bool:
        """
        Change the log level at runtime.

        Args:
            level: New log level (DEBUG, INFO, WARNING, ERROR)

        Returns:
            True if level was changed successfully
        """
        with self._config_lock:
            try:
                log_level = getattr(logging, level.upper(), None)
                if log_level is None:
                    return False

                if self._file_handler is not None:
                    self._file_handler.setLevel(log_level)

                # Also update the root logger
                root_logger = logging.getLogger("src")
                root_logger.setLevel(log_level)

                root_logger.info("Log level changed to %s", level)
                return True

            except Exception:
                return False

    def get_log_level(self) -> str:
        """
        Get the current log level name.

        Returns:
            Current log level as string (e.g., "WARNING")
        """
        with self._config_lock:
            if self._file_handler is not None:
                level = self._file_handler.level
                return logging.getLevelName(level)
            return DEFAULT_LOG_LEVEL

    def _get_log_files_unlocked(self) -> list[Path]:
        """
        Get list of all log files without acquiring lock.

        Internal method for use within methods that already hold the lock.

        Returns:
            List of Path objects for all log files, sorted by name
        """
        if self._log_dir is None or not self._log_dir.exists():
            return []

        # Match main log file and rotated backups (e.g., clamui.log.1)
        log_files = list(self._log_dir.glob("clamui.log*"))
        return sorted(log_files)

    def get_log_files(self) -> list[Path]:
        """
        Get list of all log files (current + rotated backups).

        Returns:
            List of Path objects for all log files, sorted by name
        """
        with self._config_lock:
            return self._get_log_files_unlocked()

    def get_log_dir(self) -> Path:
        """
        Get the log directory path.

        Returns:
            Path to the log directory
        """
        return self._log_dir

    def get_total_log_size(self) -> int:
        """
        Get total size of all log files in bytes.

        Returns:
            Total size in bytes
        """
        total = 0
        for log_file in self.get_log_files():
            try:
                total += log_file.stat().st_size
            except (OSError, FileNotFoundError):
                continue
        return total

    def clear_logs(self) -> bool:
        """
        Delete all log files.

        Returns:
            True if all files were deleted successfully
        """
        with self._config_lock:
            try:
                # Close the current handler to release file locks
                if self._file_handler is not None:
                    root_logger = logging.getLogger("src")
                    root_logger.removeHandler(self._file_handler)
                    self._file_handler.close()
                    self._file_handler = None

                # Delete all log files
                success = True
                for log_file in self._get_log_files_unlocked():
                    try:
                        log_file.unlink()
                    except (OSError, PermissionError):
                        success = False

                self._clear_privacy_migration_state_unlocked()

                # Reconfigure logging with a fresh handler
                # (This will create a new empty log file)
                if self._log_file is not None:
                    self._file_handler = RotatingFileHandler(
                        self._log_file,
                        maxBytes=DEFAULT_MAX_BYTES,
                        backupCount=DEFAULT_BACKUP_COUNT,
                        encoding="utf-8",
                    )
                    formatter = PrivacyFormatter(LOG_FORMAT, DATE_FORMAT)
                    self._file_handler.setFormatter(formatter)

                    root_logger = logging.getLogger("src")
                    current_level = root_logger.level or logging.WARNING
                    self._file_handler.setLevel(current_level)
                    root_logger.addHandler(self._file_handler)

                    root_logger.info("Log files cleared")

                return success

            except Exception:
                return False

    def export_logs_zip(self, output_path: Path | str) -> bool:
        """
        Export all log files to a ZIP archive.

        Args:
            output_path: Path for the output ZIP file

        Returns:
            True if export succeeded
        """
        with self._config_lock:
            try:
                self._sanitize_existing_log_files_locked(force_full=True)
                output_path = Path(output_path)
                log_files = self._get_log_files_unlocked()

                if not log_files:
                    return False

                # Create ZIP archive
                with zipfile.ZipFile(output_path, "w", zipfile.ZIP_DEFLATED) as zf:
                    for log_file in log_files:
                        # Use just the filename in the archive
                        zf.write(log_file, log_file.name)

                # Log the export
                logger = logging.getLogger("src")
                logger.info(
                    "Exported %d log file(s) to %s",
                    len(log_files),
                    sanitize_path_for_logging(str(output_path)),
                )

                return True

            except (OSError, zipfile.BadZipFile) as e:
                logger = logging.getLogger("src")
                logger.error("Failed to export logs: %s", e)
                return False

    def generate_export_filename(self) -> str:
        """
        Generate a timestamped filename for log export.

        Returns:
            Filename like "clamui-logs-2024-01-15-143052.zip"
        """
        timestamp = datetime.now().strftime("%Y-%m-%d-%H%M%S")
        return f"clamui-logs-{timestamp}.zip"


# Module-level singleton instance
_config = LoggingConfig()


def configure_logging(
    log_level: str = DEFAULT_LOG_LEVEL,
    max_bytes: int = DEFAULT_MAX_BYTES,
    backup_count: int = DEFAULT_BACKUP_COUNT,
    log_dir: Path | str | None = None,
) -> bool:
    """
    Configure the ClamUI logging system.

    This is the main entry point for setting up logging. Should be called
    early in application startup, before importing modules that use logging.

    Args:
        log_level: Logging level (DEBUG, INFO, WARNING, ERROR)
        max_bytes: Maximum size per log file in bytes
        backup_count: Number of backup files to keep
        log_dir: Optional custom log directory

    Returns:
        True if configuration succeeded
    """
    return _config.configure(
        log_dir=log_dir,
        log_level=log_level,
        max_bytes=max_bytes,
        backup_count=backup_count,
    )


def get_logging_config() -> LoggingConfig:
    """
    Get the LoggingConfig singleton instance.

    Returns:
        The LoggingConfig instance for managing logs
    """
    return _config
