import argparse
import sys
from pathlib import Path

from ..core.utils import get_config_manager
from ..logger import get_logger

logger = get_logger("cli.config")


class ConfigCLI:
    def __init__(self):
        self._config_manager = None

    @property
    def config_manager(self):
        if self._config_manager is None:
            self._config_manager = get_config_manager()
        return self._config_manager

    def create_parser(self) -> argparse.ArgumentParser:
        parser = argparse.ArgumentParser(
            prog="ludi config", description="LUDI configuration management"
        )

        subparsers = parser.add_subparsers(
            dest="command", help="Configuration commands"
        )

        show_parser = subparsers.add_parser("show", help="Show current configuration")
        show_parser.add_argument(
            "--validate", action="store_true", help="Validate configuration"
        )

        discover_parser = subparsers.add_parser(
            "discover", help="Auto-discover decompilers"
        )
        discover_parser.add_argument(
            "--save", action="store_true", help="Save discovered paths to config"
        )

        set_parser = subparsers.add_parser("set", help="Set configuration values")
        set_parser.add_argument("backend", help="Backend to configure")
        set_parser.add_argument("--path", help="Path to decompiler executable")
        set_parser.add_argument("--enabled", type=bool, help="Enable/disable backend")
        set_parser.add_argument(
            "--default", action="store_true", help="Set as default backend"
        )

        test_parser = subparsers.add_parser(
            "test", help="Test decompiler installations"
        )
        test_parser.add_argument(
            "backend", nargs="?", help="Specific backend to test (default: all)"
        )

        reset_parser = subparsers.add_parser("reset", help="Reset configuration")
        reset_parser.add_argument(
            "--confirm", action="store_true", help="Confirm reset operation"
        )

        return parser

    def show_config(self, validate: bool = False):
        print(f"Config file: {self.config_manager._config_path}")
        print(f"Config file exists: {self.config_manager._config_path.exists()}")
        print()

        if self.config_manager._config_path.exists():
            with open(self.config_manager._config_path) as f:
                print(f.read())
        else:
            print(
                "No configuration file found. Run 'ludi config discover --save' to generate one."
            )

        if validate:
            config = self.config_manager.load_config()
            print("\nValidation Results:")
            print("-" * 20)
            available_backends = self.config_manager.get_available_backend_configs()
            for name in config.keys():
                if name in available_backends:
                    print(f"  {name}: ✓ Valid")
                else:
                    config[name]
                    if name in self.config_manager._backends:
                        print(f"  {name}: ✗ Invalid (check configuration)")
                    else:
                        print(f"  {name}: ⚠ No validator (unknown backend type)")

    def discover_tools(self, save: bool = False):
        print("Discovering decompiler installations...")
        print("=" * 40)

        backends = self.config_manager._backends.values()
        discovered_any = False

        for backend_wrapper in backends:
            success, discovered = backend_wrapper.auto_discover()
            if success and "path" in discovered:
                print(f"✓ {backend_wrapper.backend_name.upper()}: {discovered['path']}")
                discovered_any = True
            else:
                print(f"✗ {backend_wrapper.backend_name.upper()}: Not found")

        if save and discovered_any:
            print(f"\nConfiguration saved to {self.config_manager._config_path}")
        elif save:
            print("\nNo tools discovered, configuration not modified")

        print("\nSystem Information:")
        print("-" * 20)
        import os
        import platform

        system_info = {
            "platform": platform.system(),
            "architecture": platform.machine(),
            "python_version": platform.python_version(),
            "home_directory": str(Path.home()),
            "path_env": os.environ.get("PATH", ""),
        }
        for key, value in system_info.items():
            if key == "path_env":
                value = value[:100] + "..." if len(value) > 100 else value
            print(f"  {key}: {value}")

    def set_config(
        self,
        backend: str,
        path: str = None,
        enabled: bool = None,
        default: bool = False,
    ):
        config = self.config_manager.load_config()

        if backend not in config:
            print(f"Error: Backend '{backend}' not found in configuration")
            return

        backend_config = config[backend]
        changed = False

        if path:
            backend_config.path = path
            backend_config.autodiscover = False
            changed = True
            print(f"Set {backend} path to: {path}")
            print(f"Disabled autodiscover for {backend}")

        if enabled is not None:
            backend_config.enabled = enabled
            changed = True
            print(f"Set {backend} enabled to: {enabled}")

        if default:
            print("Note: Default backend setting not yet implemented")
            changed = True

        if changed:
            self.config_manager.save_config()
            print(f"Configuration saved to {self.config_manager._config_path}")
        else:
            print("No changes made")

    def test_installations(self, backend: str = None):
        self.config_manager.load_config()
        backends = self.config_manager.get_backends()

        if backend:
            backends = [b for b in backends if b.backend_name == backend]
            if not backends:
                print(f"Error: Unknown backend '{backend}'")
                return

        print("Testing decompiler installations...")
        print("=" * 35)

        for backend_wrapper in backends:
            # Skip auto backend in test
            if backend_wrapper.backend_name == "auto":
                continue

            backend_config = self.config_manager.get_config(
                backend_wrapper.backend_name
            )
            if not backend_config:
                print(f"⊘ {backend_wrapper.backend_name.upper()}: Not configured")
                continue

            if not backend_config.enabled:
                print(f"⊘ {backend_wrapper.backend_name.upper()}: Disabled")
                continue

            valid = backend_wrapper.validate(backend_config)
            status = "✓ Working" if valid else "✗ Failed"
            path_info = f" ({backend_config.path})" if backend_config.path else ""
            print(f"{status} {backend_wrapper.backend_name.upper()}{path_info}")

    def reset_config(self, confirm: bool = False):
        if not confirm:
            print("This will delete your configuration file.")
            print("Use --confirm to proceed with reset.")
            return

        if self.config_manager.CONFIG_FILE.exists():
            self.config_manager.CONFIG_FILE.unlink()
            print(f"Configuration file deleted: {self.config_manager.CONFIG_FILE}")
        else:
            print("No configuration file to delete")

        self.config_manager._loaded = False
        self.config_manager._config = None

        print("Configuration reset to defaults")

    def run(self, args: list[str] = None):
        parser = self.create_parser()
        parsed_args = parser.parse_args(args)

        if not parsed_args.command:
            parser.print_help()
            return

        try:
            if parsed_args.command == "show":
                self.show_config(validate=parsed_args.validate)
            elif parsed_args.command == "discover":
                self.discover_tools(save=parsed_args.save)
            elif parsed_args.command == "set":
                self.set_config(
                    backend=parsed_args.backend,
                    path=parsed_args.path,
                    enabled=parsed_args.enabled,
                    default=parsed_args.default,
                )
            elif parsed_args.command == "test":
                self.test_installations(backend=parsed_args.backend)
            elif parsed_args.command == "reset":
                self.reset_config(confirm=parsed_args.confirm)
        except Exception as e:
            print(f"Error: {e}", file=sys.stderr)
            sys.exit(1)


def main():
    cli = ConfigCLI()
    cli.run()
