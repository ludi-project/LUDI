import os
from pathlib import Path
from typing import Any, Optional

import yaml

from ...logger import get_logger

logger = get_logger("decompilers.base.config")


class ConfigManager:
    def __init__(self, config_path: Optional[str] = None):
        if config_path:
            self._config_path = Path(config_path).expanduser()
        elif os.name == "nt":  # Windows
            config_dir = Path(os.environ.get("APPDATA", "~")) / "ludi"
            self._config_path = config_dir / "config.yaml"
        else:  # Linux/Mac
            xdg_config = os.environ.get("XDG_CONFIG_HOME", "~/.config")
            config_dir = Path(xdg_config).expanduser() / "ludi"
            self._config_path = config_dir / "config.yaml"

        self._config: dict[str, dict[str, Any]] = {}
        self._backends: dict[str, Any] = {}
        self._loaded = False

    def register_backend(self, name: str, backend_class):
        self._backends[name] = backend_class

    def load_config(self) -> dict[str, dict[str, Any]]:
        if self._loaded:
            return self._config

        if not self._config_path.exists():
            self._generate_initial_config()

        self._load_from_file()
        self._auto_discover_backends()
        self._loaded = True
        return self._config

    def _generate_initial_config(self):
        logger.info("First run detected. Generating configuration...")

        for backend in self._backends.values():
            backend_config_dict = backend.get_default_config()
            if backend_config_dict is not None:
                self._config[backend.backend_name] = backend_config_dict

        self.save_config()

        logger.info(f"Initial configuration created at: {self._config_path}")

    def _load_from_file(self):
        try:
            with open(self._config_path) as f:
                data = yaml.safe_load(f) or {}

            self._config = {}
            for name, config_dict in data.items():
                if name.startswith("_"):  # Skip metadata
                    continue

                self._config[name] = config_dict

        except Exception as e:
            logger.warning(f"Could not load config file: {e}")
            self._config = {}

    def _auto_discover_backends(self):
        for name, config in self._config.items():
            if config.get("autodiscover") and name in self._backends:
                backend = self._backends[name]
                success, discovered = backend.auto_discover()
                if success:
                    # Apply discovered values to config
                    config.update(discovered)
                    config["enabled"] = True
                else:
                    config["enabled"] = False

    def save_config(self):
        config_dict = {}
        for name, config in self._config.items():
            # Filter out None/empty values
            config_dict[name] = {
                k: v for k, v in config.items() if v is not None and v != {} and v != []
            }

        # Ensure parent directory exists
        self._config_path.parent.mkdir(parents=True, exist_ok=True)

        with open(self._config_path, "w") as f:
            yaml.dump(
                config_dict, f, default_flow_style=False, indent=2, sort_keys=False
            )

    def get_config(self, name: str) -> Optional[dict[str, Any]]:
        if not self._loaded:
            self.load_config()
        return self._config.get(name)

    def add_config(self, name: str, config: dict[str, Any]):
        if not self._loaded:
            self.load_config()
        self._config[name] = config

    def list_backend_configs(self) -> dict[str, str]:
        """List all backend configs and their types (e.g., {'ida91': 'ida', 'angr': 'angr'})."""
        if not self._loaded:
            self.load_config()
        return {name: config.get("type") for name, config in self._config.items()}

    def get_available_backend_configs(self) -> list[str]:
        """Get list of configured and enabled backend configs (e.g., ['ida91', 'ida-auto', 'angr'])."""
        if not self._loaded:
            self.load_config()

        available = []
        for name, config in self._config.items():
            if config.get("enabled", True):
                available.append(name)
        return available

    def get_working_backend_configs(self) -> list[str]:
        """Get list of backend configs that are configured, enabled, and actually working."""
        if not self._loaded:
            self.load_config()

        working = []
        for name, config in self._config.items():
            if config.get("enabled", True) and name in self._backends:
                backend = self._backends[name]
                try:
                    if backend.validate(config):
                        working.append(name)
                except Exception:
                    # If validation crashes, skip this backend
                    continue
        return working

    def get_available_backend_types(self) -> list[str]:
        """Get list of available backend types (e.g., ['ida', 'angr', 'ghidra'])."""
        return list(self._backends.keys())

    def get_backend_types(self) -> list:
        """Get list of registered backend type classes."""
        return list(self._backends.values())


_config_manager: Optional[ConfigManager] = None


def get_config_manager(config_path: Optional[str] = None) -> ConfigManager:
    global _config_manager

    # Check if config path is provided or use environment variable
    effective_config_path = config_path or os.environ.get("LUDI_CONFIG_PATH")

    # Create new manager if none exists or if config path differs
    if _config_manager is None or (
        effective_config_path
        and str(_config_manager._config_path) != str(effective_config_path)
    ):
        _config_manager = ConfigManager(effective_config_path)
    return _config_manager
