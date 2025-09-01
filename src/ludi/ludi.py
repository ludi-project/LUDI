import importlib
from pathlib import Path
from typing import Any, Dict, Optional, Type

from .decompilers.base.config import ConfigProvider, get_config_manager
from .decompilers.base.decompiler import DecompilerBase
from .logger import get_logger

logger = get_logger("ludi")


def _get_backend_directories() -> list[Path]:
    decompilers_path = Path(__file__).parent / "decompilers"
    return [
        item
        for item in decompilers_path.iterdir()
        if item.is_dir()
        and not item.name.startswith(".")
        and item.name not in {"base", "__pycache__"}
    ]


def _discover_supported_backends() -> Dict[str, Type[DecompilerBase]]:
    backends = {}
    for item in _get_backend_directories():
        try:
            module = importlib.import_module(f"ludi.decompilers.{item.name}.decompiler")
            for attr in dir(module):
                cls = getattr(module, attr)
                if (
                    isinstance(cls, type)
                    and issubclass(cls, DecompilerBase)
                    and cls != DecompilerBase
                ):
                    backends[item.name] = cls
                    logger.debug(f"Discovered backend: {item.name} -> {cls}")
                    break
        except ImportError:
            continue
    return backends


def _register_config_providers() -> None:
    config_manager = get_config_manager()
    for item in _get_backend_directories():
        try:
            config_module = importlib.import_module(f"ludi.decompilers.{item.name}.config")
            for attr_name in dir(config_module):
                cls = getattr(config_module, attr_name)
                if (
                    isinstance(cls, type)
                    and issubclass(cls, ConfigProvider)
                    and cls != ConfigProvider
                ):
                    config_manager.register_provider(cls())
                    logger.debug(f"Registered config provider: {item.name} -> {cls}")
                    break
        except ImportError as e:
            logger.debug(f"Failed to import config for {item.name}: {e}")
            continue


SUPPORTED_BACKENDS = _discover_supported_backends()
_register_config_providers()


class LUDI:
    def __init__(
        self,
        backend: str,
        binary_path: str,
        backend_options: Optional[Dict[str, Dict[str, Any]]] = None,
        **kwargs,
    ):
        self._requested_backend = backend
        self.binary_path = binary_path

        if not Path(binary_path).exists():
            raise FileNotFoundError(f"Binary file not found: {binary_path}")

        try:
            self._decompiler = self._create_backend(backend, binary_path, backend_options, **kwargs)
        except Exception as e:
            logger.error(f"Failed to initialize backend {backend}: {e}")
            raise RuntimeError(f"Failed to initialize backend {backend}: {e}") from e

    def _create_backend(
        self,
        backend: str,
        binary_path: str,
        backend_options: Optional[Dict[str, Dict[str, Any]]] = None,
        **kwargs,
    ) -> DecompilerBase:
        config_manager = get_config_manager()
        config_manager.load_config()

        if ":" in backend:
            primary_name, target_backend = backend.split(":", 1)
            config = config_manager.get_config(primary_name)
            if not config:
                raise ValueError(f"No configuration found for: {primary_name}")
            if config.type not in SUPPORTED_BACKENDS:
                raise ValueError(f"Unknown backend type: {config.type}")

            final_kwargs = kwargs.copy()
            if backend_options and config.type in backend_options:
                final_kwargs.update(backend_options[config.type])

            return SUPPORTED_BACKENDS[config.type](
                binary_path, config.__dict__, target_backend, **final_kwargs
            )

        config = config_manager.get_config(backend)
        if not config:
            if backend == "auto":
                from .decompilers.base.config import BackendConfig
                config = BackendConfig(type="auto")
            else:
                raise ValueError(f"No configuration found for backend: {backend}")
        if config.type not in SUPPORTED_BACKENDS:
            raise ValueError(f"Unknown backend type: {config.type}")

        final_kwargs = kwargs.copy()
        if backend_options and config.type in backend_options:
            final_kwargs.update(backend_options[config.type])

        if "path" not in final_kwargs:
            path_to_use = config.path
            if config.autodiscover and not path_to_use and config.type in config_manager._providers:
                path_to_use = config_manager._providers[config.type].auto_discover()
            if path_to_use:
                final_kwargs["path"] = path_to_use

        return SUPPORTED_BACKENDS[config.type](binary_path, **final_kwargs)

    def __enter__(self) -> "LUDI":
        return self

    def __exit__(
        self,
        _exc_type: Optional[type],
        _exc_val: Optional[BaseException],
        _exc_tb: Optional[object],
    ) -> None:
        self.close()

    def close(self) -> None:
        if hasattr(self._decompiler, "close"):
            self._decompiler.close()

    def __getattr__(self, name: str):
        if hasattr(self._decompiler, name):
            return getattr(self._decompiler, name)
        raise AttributeError(f"'{self.__class__.__name__}' object has no attribute '{name}'")

    @property
    def backend_name(self) -> str:
        if hasattr(self._decompiler, "backend_name"):
            return self._decompiler.backend_name
        return self._requested_backend
