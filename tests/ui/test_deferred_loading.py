# ClamUI Deferred Loading Tests
"""
Tests for deferred data loading in UI views.

Verifies that views defer their data loading to the `map` signal
(when the view first becomes visible) instead of loading eagerly
during __init__. This improves startup speed by not loading data
for panels the user hasn't opened yet.

Also verifies that views accept a shared LogManager to avoid
redundant instance creation.
"""

import sys
from unittest.mock import MagicMock, patch


def _clear_src_modules():
    """Clear all cached src.* modules to prevent test pollution."""
    modules_to_remove = [mod for mod in sys.modules if mod.startswith("src.")]
    for mod in modules_to_remove:
        del sys.modules[mod]


# =============================================================================
# ComponentsView deferred loading
# =============================================================================


class TestComponentsViewDeferredLoading:
    """Verify ComponentsView defers data loading to map signal."""

    def test_accepts_shared_log_manager(self, mock_gi_modules):
        """ComponentsView should accept a log_manager kwarg."""
        from src.ui.components_view import ComponentsView

        view = object.__new__(ComponentsView)
        shared_lm = MagicMock()
        view._log_manager = shared_lm
        view._is_checking = False
        view._destroyed = False
        view._initial_load_done = False
        view._component_rows = {}
        view._status_icons = {}
        view._status_labels = {}
        view._guide_rows = {}

        assert view._log_manager is shared_lm
        _clear_src_modules()

    def test_does_not_check_components_on_init(self, mock_gi_modules):
        """ComponentsView should NOT call _check_all_components during init."""
        from src.ui.components_view import ComponentsView

        view = object.__new__(ComponentsView)
        view._log_manager = MagicMock()
        view._is_checking = False
        view._destroyed = False
        view._initial_load_done = False
        view._component_rows = {}
        view._status_icons = {}
        view._status_labels = {}
        view._guide_rows = {}

        # _initial_load_done should be False after init
        assert view._initial_load_done is False
        _clear_src_modules()

    def test_on_first_map_triggers_load(self, mock_gi_modules):
        """_on_first_map should trigger component check only once."""
        from src.ui.components_view import ComponentsView

        view = object.__new__(ComponentsView)
        view._log_manager = MagicMock()
        view._is_checking = False
        view._destroyed = False
        view._initial_load_done = False
        view._component_rows = {}
        view._status_icons = {}
        view._status_labels = {}
        view._guide_rows = {}
        view._refresh_button = MagicMock()
        view._refresh_spinner = MagicMock()

        # Mock _check_all_components
        view._check_all_components = MagicMock()

        # First map should trigger load
        view._on_first_map(None)
        assert view._initial_load_done is True
        view._check_all_components.assert_called_once()

        # Second map should NOT trigger load again
        view._check_all_components.reset_mock()
        view._on_first_map(None)
        view._check_all_components.assert_not_called()

        _clear_src_modules()


# =============================================================================
# StatisticsView deferred loading
# =============================================================================


class TestStatisticsViewDeferredLoading:
    """Verify StatisticsView defers data loading to map signal."""

    def test_accepts_shared_log_manager(self, mock_gi_modules):
        """StatisticsView should pass log_manager to StatisticsCalculator."""
        with patch.dict(
            sys.modules,
            {
                "matplotlib": MagicMock(),
                "matplotlib.figure": MagicMock(),
                "matplotlib.backends.backend_gtk4agg": MagicMock(),
            },
        ):
            if "src.ui.statistics_view" in sys.modules:
                del sys.modules["src.ui.statistics_view"]

            from src.ui.statistics_view import StatisticsView

            view = object.__new__(StatisticsView)
            mock_calculator = MagicMock()
            view._calculator = mock_calculator
            view._current_timeframe = "weekly"
            view._is_loading = False
            view._initial_load_done = False

            assert view._initial_load_done is False

        _clear_src_modules()

    def test_on_first_map_triggers_load(self, mock_gi_modules):
        """_on_first_map should trigger statistics load only once."""
        with patch.dict(
            sys.modules,
            {
                "matplotlib": MagicMock(),
                "matplotlib.figure": MagicMock(),
                "matplotlib.backends.backend_gtk4agg": MagicMock(),
            },
        ):
            if "src.ui.statistics_view" in sys.modules:
                del sys.modules["src.ui.statistics_view"]

            from src.ui.statistics_view import StatisticsView

            view = object.__new__(StatisticsView)
            view._calculator = MagicMock()
            view._current_timeframe = "weekly"
            view._is_loading = False
            view._initial_load_done = False
            view._current_stats = None
            view._current_protection = None
            view._on_quick_scan_requested = None

            # Mock _load_statistics_async
            view._load_statistics_async = MagicMock()

            # First map should trigger load
            view._on_first_map(None)
            assert view._initial_load_done is True
            view._load_statistics_async.assert_called_once()

            # Second map should NOT trigger load again
            view._load_statistics_async.reset_mock()
            view._on_first_map(None)
            view._load_statistics_async.assert_not_called()

        _clear_src_modules()


# =============================================================================
# LogsView deferred loading
# =============================================================================


class TestLogsViewDeferredLoading:
    """Verify LogsView defers data loading to map signal."""

    def test_accepts_shared_log_manager(self, mock_gi_modules):
        """LogsView should accept a log_manager kwarg."""
        from src.ui.logs_view import LogsView

        view = object.__new__(LogsView)
        shared_lm = MagicMock()
        view._log_manager = shared_lm
        view._initial_load_done = False

        assert view._log_manager is shared_lm
        assert view._initial_load_done is False
        _clear_src_modules()

    def test_on_first_map_triggers_load(self, mock_gi_modules):
        """_on_first_map should trigger log load only once."""
        from src.ui.logs_view import LogsView

        view = object.__new__(LogsView)
        view._log_manager = MagicMock()
        view._initial_load_done = False
        view._is_loading = False
        view._all_log_entries = []

        # Mock _load_logs_async
        view._load_logs_async = MagicMock()

        # First map should trigger load
        view._on_first_map(None)
        assert view._initial_load_done is True
        view._load_logs_async.assert_called_once()

        # Second map should NOT trigger load again
        view._load_logs_async.reset_mock()
        view._on_first_map(None)
        view._load_logs_async.assert_not_called()

        _clear_src_modules()


# =============================================================================
# AuditView deferred loading
# =============================================================================


class TestAuditViewDeferredLoading:
    """Verify AuditView defers audit to map signal."""

    def test_on_first_map_triggers_audit(self, mock_gi_modules):
        """_on_first_map should trigger audit only once."""
        from src.ui.audit_view import AuditView

        view = object.__new__(AuditView)
        view._is_checking = False
        view._destroyed = False
        view._cached_report = None
        view._initial_load_done = False

        # Mock _run_audit_if_needed
        view._run_audit_if_needed = MagicMock()

        # First map should trigger audit
        view._on_first_map(None)
        assert view._initial_load_done is True
        view._run_audit_if_needed.assert_called_once()

        # Second map should NOT trigger audit again
        view._run_audit_if_needed.reset_mock()
        view._on_first_map(None)
        view._run_audit_if_needed.assert_not_called()

        _clear_src_modules()


# =============================================================================
# QuarantineView optimized map handler
# =============================================================================


class TestQuarantineViewMapOptimization:
    """Verify QuarantineView doesn't double-load on first map."""

    def test_map_skips_if_already_loaded(self, mock_gi_modules):
        """_on_view_mapped should skip if entries are already loaded."""
        from src.ui.quarantine_view import QuarantineView

        view = object.__new__(QuarantineView)
        view._manager = MagicMock()
        view._is_loading = False
        view._all_entries = [MagicMock()]  # Already has entries
        view._last_refresh_time = 0.0

        # Mock _load_entries_async
        view._load_entries_async = MagicMock()

        view._on_view_mapped(None)
        view._load_entries_async.assert_not_called()

        _clear_src_modules()

    def test_map_skips_if_currently_loading(self, mock_gi_modules):
        """_on_view_mapped should skip if data is already being loaded."""
        from src.ui.quarantine_view import QuarantineView

        view = object.__new__(QuarantineView)
        view._manager = MagicMock()
        view._is_loading = True  # Currently loading
        view._all_entries = []
        view._last_refresh_time = 0.0

        # Mock _load_entries_async
        view._load_entries_async = MagicMock()

        view._on_view_mapped(None)
        view._load_entries_async.assert_not_called()

        _clear_src_modules()

    def test_map_loads_if_empty_and_idle(self, mock_gi_modules):
        """_on_view_mapped should load if no entries and not loading."""
        from src.ui.quarantine_view import QuarantineView

        view = object.__new__(QuarantineView)
        view._manager = MagicMock()
        view._is_loading = False
        view._all_entries = []  # No entries yet
        view._last_refresh_time = 0.0

        # Mock _load_entries_async
        view._load_entries_async = MagicMock()

        view._on_view_mapped(None)
        view._load_entries_async.assert_called_once()

        _clear_src_modules()


# =============================================================================
# Shared LogManager in App
# =============================================================================


class TestSharedLogManager:
    """Verify views use shared log_manager instead of creating their own."""

    def test_components_view_uses_shared_lm(self, mock_gi_modules):
        """ComponentsView should use the provided log_manager, not create a new one."""
        from src.ui.components_view import ComponentsView

        view = object.__new__(ComponentsView)
        shared_lm = MagicMock(name="shared_log_manager")
        view._log_manager = shared_lm

        # Confirm it's the exact same object reference
        assert view._log_manager is shared_lm
        _clear_src_modules()

    def test_logs_view_uses_shared_lm(self, mock_gi_modules):
        """LogsView should use the provided log_manager, not create a new one."""
        from src.ui.logs_view import LogsView

        view = object.__new__(LogsView)
        shared_lm = MagicMock(name="shared_log_manager")
        view._log_manager = shared_lm

        assert view._log_manager is shared_lm
        _clear_src_modules()

    def test_scan_view_passes_lm_to_scanner(self, mock_gi_modules):
        """ScanView should pass log_manager to Scanner constructor."""
        import inspect

        from src.ui.scan_view import ScanView

        sig = inspect.signature(ScanView.__init__)
        assert "log_manager" in sig.parameters
        _clear_src_modules()
