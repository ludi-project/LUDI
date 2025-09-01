import importlib
from pathlib import Path
from typing import Any, Optional

from ..backends.base.config import get_config_manager
from ..backends.base.decompiler import DecompilerBase
from ..logger import get_logger

logger = get_logger("ludi")


def _get_backend_directories() -> list[Path]:
    backends_path = Path(__file__).parent.parent / "backends"
    return [
        item
        for item in backends_path.iterdir()
        if item.is_dir()
        and not item.name.startswith(".")
        and item.name not in {"base", "__pycache__"}
    ]


def _discover_supported_backends() -> dict[str, Any]:
    backends = {}
    for item in _get_backend_directories():
        try:
            module = importlib.import_module(f"ludi.backends.{item.name}.decompiler")
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
                # Check for factory functions (like AutoDecompiler)
                elif (
                    callable(cls)
                    and not isinstance(cls, type)
                    and not attr.startswith("_")
                    and attr.endswith("Decompiler")
                ):
                    backends[item.name] = cls
                    logger.debug(f"Discovered function: {item.name} -> {cls}")
                    break
        except ImportError:
            continue
    return backends


def _register_backends() -> None:
    config_manager = get_config_manager()

    for backend_name, backend_class in SUPPORTED_BACKENDS.items():
        config_manager.register_backend(backend_name, backend_class)
        logger.debug(f"Registered backend: {backend_name} -> {backend_class}")


SUPPORTED_BACKENDS = _discover_supported_backends()
_register_backends()


def create_backend(
    backend_configuration: str,
    binary_path: str,
    backend_options: Optional[dict[str, dict[str, Any]]] = None,
    config_path: Optional[str] = None,
    **kwargs,
) -> DecompilerBase:
    """Create a backend instance."""
    return _create_backend_impl(
        backend_configuration, binary_path, backend_options, config_path, **kwargs
    )


def _load_env_vars(backend_type: str, kwargs: dict) -> None:
    """Load backend-specific environment variables."""
    import os
    import json

    prefix = f"LUDI_{backend_type.upper()}_"
    for env_key, env_value in os.environ.items():
        if env_key.startswith(prefix):
            setting_name = env_key[len(prefix) :].lower()
            # Try to parse as JSON for complex values, fallback to string
            try:
                kwargs[setting_name] = json.loads(env_value)
            except (json.JSONDecodeError, ValueError):
                kwargs[setting_name] = env_value


def _create_backend_impl(
    backend_configuration: str,
    binary_path: str,
    backend_options: Optional[dict[str, dict[str, Any]]] = None,
    config_path: Optional[str] = None,
    **kwargs,
) -> DecompilerBase:
    """Backend creation implementation."""
    config_manager = get_config_manager(config_path)
    config_manager.load_config()

    if ":" in backend_configuration:
        primary_name, target_backend = backend_configuration.split(":", 1)
        config = config_manager.get_config(primary_name)
        if not config:
            raise ValueError(f"No configuration found for: {primary_name}")
        backend_type = config.get("type")
        if backend_type not in SUPPORTED_BACKENDS:
            raise ValueError(f"Unknown backend type: {backend_type}")

        # Same priority order: Direct kwargs > backend_options > environment vars
        final_kwargs = {}

        # Lowest priority: environment variables
        _load_env_vars(backend_type, final_kwargs)

        # Middle priority: backend_options
        if backend_options and backend_type in backend_options:
            final_kwargs.update(backend_options[backend_type])

        # Highest priority: direct kwargs
        final_kwargs.update(kwargs)

        return SUPPORTED_BACKENDS[backend_type](
            binary_path, config, target_backend, **final_kwargs
        )

    config = config_manager.get_config(backend_configuration)
    if not config:
        # For backends like auto that don't appear in config, create minimal config
        if backend_configuration in SUPPORTED_BACKENDS:
            config = {"type": backend_configuration}
        else:
            raise ValueError(
                f"No configuration found for backend: {backend_configuration}"
            )
    backend_type = config.get("type")
    if backend_type not in SUPPORTED_BACKENDS:
        raise ValueError(f"Unknown backend type: {backend_type}")

    # Priority order: Direct kwargs > backend_options > environment vars
    final_kwargs = {}

    # Lowest priority: environment variables
    _load_env_vars(backend_type, final_kwargs)

    # Middle priority: backend_options
    if backend_options and backend_type in backend_options:
        final_kwargs.update(backend_options[backend_type])

    # Highest priority: direct kwargs (overwrites everything)
    final_kwargs.update(kwargs)

    if "path" not in final_kwargs:
        path_to_use = config.get("path")
        if (
            config.get("autodiscover")
            and not path_to_use
            and backend_type in config_manager._backends
        ):
            success, discovered = config_manager._backends[backend_type].auto_discover()
            if success and "path" in discovered:
                path_to_use = discovered["path"]
        if path_to_use:
            final_kwargs["path"] = path_to_use

    backend_class = SUPPORTED_BACKENDS[backend_type]

    # Duck typing - check for different backend types
    if callable(backend_class) and not isinstance(backend_class, type):
        # Factory function (like auto backend)
        return backend_class(binary_path, **final_kwargs)
    else:
        # Normal backend class
        return backend_class(binary_path, **final_kwargs)
