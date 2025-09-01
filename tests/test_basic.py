"""Basic LUDI functionality test with real binary."""

import ludi


def test_ludi_basic_usage():
    """Test basic LUDI usage with /bin/ls to get main function info."""
    analyzer = ludi.auto(
        "/bin/ls",
        backend_options={"angr": {"auto_load_libs": False, "load_debug_info": False}},
    )

    main_func = analyzer.functions.by_name("main")

    if main_func:
        assert main_func.name == "main"
        assert main_func.start > 0

    functions = analyzer.functions.all()
    assert len(functions) > 0, "Should find at least some functions in /bin/ls"

    analyzer.close()


def test_ludi_shell_integration():
    """Test LUDI through shell-like interface (CLI functions)."""
    import sys
    from unittest.mock import patch

    from ludi.cli.main import _handle_binary_execution

    original_argv = sys.argv
    try:
        sys.argv = ["ludi", "/bin/ls"]

        with patch("ludi.cli.main._start_binary_shell") as mock_shell:

            def mock_shell_func(analyzer, binary_path):
                main_func = analyzer.functions.by_name("main")
                if main_func:
                    assert main_func.start > 0
                    assert main_func.name == "main"

                functions = analyzer.functions.all()
                assert len(functions) > 0
                return

            mock_shell.side_effect = mock_shell_func

            _handle_binary_execution()

    finally:
        sys.argv = original_argv


if __name__ == "__main__":
    test_ludi_basic_usage()
    test_ludi_shell_integration()
