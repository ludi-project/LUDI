"""angr configuration management."""

import os
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from ..base.config import ConfigProvider, BackendConfig, get_config_manager


@dataclass
class AngrConfig:
    """angr configuration."""
    auto_load_libs: bool = False
    use_sim_procedures: bool = True
    load_debug_info: bool = True


class AngrConfigProvider(ConfigProvider):
    """angr-specific configuration provider."""
    
    def __init__(self):
        self._config = BackendConfig(enabled=True)  # Angr is enabled by default if importable
    
    @property
    def backend_name(self) -> str:
        return "angr"
    
    def get_config(self) -> BackendConfig:
        return self._config
    
    def set_config(self, config: BackendConfig) -> None:
        self._config = config
    
    def auto_discover(self) -> Optional[str]:
        """Auto-discover angr installation (Python package)."""
        try:
            import angr
            # For Python packages, return the actual package directory
            if hasattr(angr, '__path__') and angr.__path__:
                return str(Path(angr.__path__[0]))
            return None
        except ImportError:
            return None
    
    def validate(self, path: Optional[str] = None) -> bool:
        """Validate angr installation."""
        if path is None:
            path = self._config.path
            
        if not path:
            return False
            
        # For angr, we just need to check if it's importable
        try:
            import angr
            return True
        except ImportError:
            return False


def get_angr_config() -> AngrConfig:
    """Get angr configuration from environment."""
    auto_load_libs = os.environ.get('LUDI_ANGR_AUTO_LOAD_LIBS', 'false').lower() == 'true'
    use_sim_procedures = os.environ.get('LUDI_ANGR_USE_SIM_PROCEDURES', 'true').lower() == 'true'
    load_debug_info = os.environ.get('LUDI_ANGR_LOAD_DEBUG_INFO', 'true').lower() == 'true'
    
    return AngrConfig(
        auto_load_libs=auto_load_libs,
        use_sim_procedures=use_sim_procedures,
        load_debug_info=load_debug_info
    )


# Auto-register angr provider when this module is imported
_angr_provider = AngrConfigProvider()
get_config_manager().register_provider(_angr_provider)