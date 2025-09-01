from ludi.cli.config import get_config_manager
from ludi.core.ludi import SUPPORTED_BACKENDS
import ludi


class TestBackendInitialization:
    def test_supported_backends_discovery(self):
        """Test that backends are discovered properly"""
        assert len(SUPPORTED_BACKENDS) > 0
        expected_backends = ["ida", "angr", "ghidra", "auto"]

        for backend in expected_backends:
            assert backend in SUPPORTED_BACKENDS, f"Backend {backend} not found"

    def test_config_manager_loading(self):
        """Test that config manager loads configuration properly"""
        manager = get_config_manager()
        assert manager is not None
        assert manager._config_path.exists(), "Config file should exist"

    def test_backend_availability_check(self):
        """Test checking which backends are actually available"""
        print("\nBackend availability:")
        for name, _ in SUPPORTED_BACKENDS.items():
            try:
                # Try to get config for this backend
                manager = get_config_manager()
                config = manager.get_backend_config(name)
                print(f"  {name}: config={config}")

            except Exception as e:
                print(f"  {name}: failed with {type(e).__name__}: {e}")

    def test_ludi_load_binary(self):
        """Test the actual LUDI load that's failing"""
        print("\nTesting LUDI load /bin/ls:")

        # Test angr backend (should work after fixes)
        try:
            analyzer = ludi.analyze("/bin/ls", backend="angr")
            print(f"  angr: SUCCESS - found {len(analyzer.functions.all())} functions")
            analyzer.close()
        except Exception as e:
            print(f"  angr: FAILED - {e}")

        # Test IDA backend (should work if path is configured)
        try:
            analyzer = ludi.analyze("/bin/ls", backend="ida")
            print("  ida: SUCCESS")
            analyzer.close()
        except Exception as e:
            print(f"  ida: FAILED - {e}")

        # Test auto backend (should work and fall back to working backend)
        try:
            analyzer = ludi.analyze("/bin/ls")
            backend_type = type(analyzer).__name__
            print(f"  auto: SUCCESS - using {backend_type}")
            analyzer.close()
        except Exception as e:
            print(f"  auto: FAILED - {e}")

    def test_dynamic_command_execution(self):
        """Test the dynamic CLI command execution"""
        try:
            analyzer = ludi.analyze("/bin/ls", backend="angr")

            # Test the _execute_binary_command function
            from ludi.cli.main import _execute_binary_command

            print("\nTesting dynamic commands:")
            print("Functions:", end=" ")
            _execute_binary_command(analyzer, "functions")

            analyzer.close()

        except Exception as e:
            print(f"Command execution test failed: {e}")


if __name__ == "__main__":
    test = TestBackendInitialization()
    test.test_supported_backends_discovery()
    test.test_config_manager_loading()
    test.test_backend_availability_check()
    test.test_ludi_load_binary()
