from typing import Any

from ...logger import get_logger
from ..base.config import get_config_manager
from ..base.decompiler import DecompilerBase

logger = get_logger("decompilers.auto")


def auto_select_decompiler(binary_path: str, **kwargs) -> DecompilerBase:
    config_manager = get_config_manager()
    available_backends = config_manager.get_available_backend_configs()

    available_backends = [b for b in available_backends if b != "auto"]

    if not available_backends:
        raise RuntimeError("No backends available for auto selection")

    errors = []
    for backend_type in available_backends:
        try:
            # Create backend for this backend type
            from ...core.ludi import create_backend

            return create_backend(backend_type, binary_path, **kwargs)
        except Exception as e:
            logger.debug(f"Auto selection failed for {backend_type}: {e}")
            errors.append(f"{backend_type}: {e}")
            continue

    raise RuntimeError(f"No working backend found. Tried: {'; '.join(errors)}")


# Configuration methods for auto backend
def get_backend_name() -> str:
    return "auto"


def auto_discover(**kwargs) -> tuple[bool, dict[str, Any]]:
    return False, {}


def get_default_config() -> dict:
    # Auto backend should not be in config file
    return None


def validate(config) -> bool:
    return True


# This is what gets registered in SUPPORTED_BACKENDS
AutoDecompiler = auto_select_decompiler
