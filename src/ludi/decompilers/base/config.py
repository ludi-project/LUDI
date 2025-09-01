import os
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

import yaml

from ...logger import get_logger

logger = get_logger("decompilers.base.config")


@dataclass
class BackendConfig:
    type: str  # Backend type name
    autodiscover: bool = False

    path: Optional[str] = None
    enabled: bool = True

    server: Optional[str] = None
    port: Optional[int] = None
    protocol: str = "http"
    auth: Dict[str, Any] = field(default_factory=dict)

    options: Dict[str, Any] = field(default_factory=dict)


class ConfigProvider(ABC):
    @property
    @abstractmethod
    def backend_name(self) -> str:
        pass

    @abstractmethod
    def auto_discover(self) -> Optional[str]:
        pass

    @abstractmethod
    def validate(self, path: Optional[str] = None) -> bool:
        pass

    def run_script(self, script_path: str, binary_path: str = None, script_args: list = None):
        raise NotImplementedError(f"Script execution not supported for {self.backend_name} backend")


class ConfigManager:
    def __init__(self):
        self._config_path = self._get_config_path()
        self._config: Dict[str, BackendConfig] = {}
        self._providers: Dict[str, ConfigProvider] = {}
        self._loaded = False

    def _get_config_path(self) -> Path:
        if os.name == "nt":  # Windows
            config_dir = Path(os.environ.get("APPDATA", "~")) / "ludi"
        else:  # Linux/Mac
            xdg_config = os.environ.get("XDG_CONFIG_HOME", "~/.config")
            config_dir = Path(xdg_config).expanduser() / "ludi"
        return config_dir / "config.yaml"

    def register_provider(self, provider: ConfigProvider):
        self._providers[provider.backend_name] = provider

    def load_config(self) -> Dict[str, BackendConfig]:
        if self._loaded:
            return self._config

        if not self._config_path.exists():
            self._generate_initial_config()

        self._load_from_file()
        self._update_autodiscovered()
        self._loaded = True
        return self._config

    def _generate_initial_config(self):
        logger.info("First run detected. Generating configuration...")

        config = {}

        for provider in self._providers.values():
            if provider.backend_name == "auto":
                continue

            discovered_path = provider.auto_discover()
            if discovered_path and provider.validate(discovered_path):
                config[provider.backend_name] = {
                    "type": provider.backend_name,
                    "autodiscover": True,
                }
            else:
                config[provider.backend_name] = {
                    "type": provider.backend_name,
                    "autodiscover": True,
                    "enabled": False,
                }

        self._config_path.parent.mkdir(parents=True, exist_ok=True)
        with open(self._config_path, "w") as f:
            f.write("# LUDI configuration file - named backends\n")
            f.write("# Edit this file to add custom backends or disable autodiscovery\n")
            f.write("\n")

            yaml.dump(config, f, default_flow_style=False, indent=2, sort_keys=False)

        logger.info(f"Configuration created at: {self._config_path}")
        logger.info("Edit this file to add custom backends or disable autodiscovery")

    def _load_from_file(self):
        try:
            with open(self._config_path) as f:
                data = yaml.safe_load(f) or {}

            self._config = {}
            for name, config_dict in data.items():
                if name.startswith("_"):  # Skip metadata
                    continue

                self._config[name] = BackendConfig(**config_dict)

        except Exception as e:
            logger.warning(f"Could not load config file: {e}")
            self._config = {}

    def _update_autodiscovered(self):
        for name, config in self._config.items():
            if config.type == "local" and config.autodiscover:
                if name in self._providers:
                    provider = self._providers[name]
                    discovered_path = provider.auto_discover()
                    if discovered_path and provider.validate(discovered_path):
                        config.path = discovered_path
                        config.enabled = True
                    else:
                        config.enabled = False

    def save_config(self):
        config_dict = {}

        for name, config in self._config.items():
            entry = {"type": config.type}

            if config.autodiscover:
                entry["autodiscover"] = config.autodiscover
            if not config.enabled:
                entry["enabled"] = config.enabled
            if config.path:  # Save path when explicitly set
                entry["path"] = config.path

            if config.type == "remote":
                if config.server:
                    entry["server"] = config.server
                if config.port:
                    entry["port"] = config.port
                if config.protocol != "http":
                    entry["protocol"] = config.protocol
                if config.auth:
                    entry["auth"] = config.auth

            if config.options:
                entry["options"] = config.options

            config_dict[name] = entry

        with open(self._config_path, "w") as f:
            f.write("# LUDI configuration file - named backends\n")
            f.write("# Edit this file to add custom backends or disable autodiscovery\n")
            f.write("\n")

            yaml.dump(config_dict, f, default_flow_style=False, indent=2, sort_keys=False)

    def get_config(self, name: str) -> Optional[BackendConfig]:
        if not self._loaded:
            self.load_config()
        return self._config.get(name)

    def add_backend(self, name: str, config: BackendConfig):
        if not self._loaded:
            self.load_config()
        self._config[name] = config

    def list_backends(self) -> Dict[str, str]:
        if not self._loaded:
            self.load_config()
        return {name: config.type for name, config in self._config.items()}

    def get_available_backends(self) -> List[str]:
        if not self._loaded:
            self.load_config()

        available = []
        for name, config in self._config.items():
            if config.enabled:
                if name in self._providers:
                    provider = self._providers[name]
                    path_to_validate = config.path
                    if config.autodiscover and not path_to_validate:
                        path_to_validate = provider.auto_discover()

                    if provider.validate(path_to_validate):
                        available.append(name)
                else:
                    available.append(name)

        if available and "auto" not in available:
            available.append("auto")

        return available

    def get_backend_config(self, backend_name: str) -> Optional[BackendConfig]:
        config = self.get_config(backend_name)
        return config

    def get_providers(self) -> List[ConfigProvider]:
        return list(self._providers.values())


_config_manager = ConfigManager()


def get_config_manager() -> ConfigManager:
    return _config_manager
