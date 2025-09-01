"""Config command group - Configuration management."""
from typing import Optional


class Config:
    """Configuration management commands."""

    def __init__(self):
        from ..cli.config import ConfigCLI

        self._cli = ConfigCLI()

    def show(self, validate: bool = False):
        """Show current configuration.

        Args:
            validate: Validate configuration while showing
        """
        self._cli.show_config(validate=validate)

    def discover(self, save: bool = False):
        """Auto-discover tool installations.

        Args:
            save: Save discovered paths to configuration
        """
        self._cli.discover_tools(save=save)

    def test(self, backend: Optional[str] = None):
        """Test backend installations.

        Args:
            backend: Specific backend to test (default: test all)
        """
        self._cli.test_installations(backend=backend)

    def set(
        self,
        backend: str,
        path: Optional[str] = None,
        enabled: Optional[bool] = None,
        default: bool = False,
    ):
        """Set configuration values.

        Args:
            backend: Backend to configure
            path: Path to executable
            enabled: Enable/disable backend
            default: Set as default backend
        """
        self._cli.set_config(
            backend=backend, path=path, enabled=enabled, default=default
        )

    def reset(self, confirm: bool = False):
        """Reset configuration to defaults.

        Args:
            confirm: Confirm the reset operation
        """
        self._cli.reset_config(confirm=confirm)


# Create instance for direct access
config = Config()
