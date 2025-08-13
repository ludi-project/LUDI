import os
import yaml
from abc import ABC, abstractmethod
from pathlib import Path
from typing import Dict, Any, Optional, List
from dataclasses import dataclass, field


@dataclass
class BackendConfig:
    """Configuration for a decompiler backend."""
    path: Optional[str] = None
    enabled: bool = True
    auto_discover: bool = True
    options: Dict[str, Any] = field(default_factory=dict)


class ConfigProvider(ABC):
    """Abstract base class for decompiler-specific configuration providers."""
    
    @property
    @abstractmethod
    def backend_name(self) -> str:
        """Name of the backend (e.g., 'ida', 'ghidra', 'angr')."""
        pass
    
    @abstractmethod
    def get_config(self) -> BackendConfig:
        """Get current configuration for this backend."""
        pass
    
    @abstractmethod
    def set_config(self, config: BackendConfig) -> None:
        """Set configuration for this backend."""
        pass
    
    @abstractmethod
    def auto_discover(self) -> Optional[str]:
        """Auto-discover installation path for this backend."""
        pass
    
    @abstractmethod
    def validate(self, path: Optional[str] = None) -> bool:
        """Validate backend installation."""
        pass
    
    def is_available(self) -> bool:
        """Check if this backend is available and working."""
        config = self.get_config()
        return config.enabled and self.validate(config.path)


@dataclass
class LudiConfig:
    """Main LUDI configuration."""
    default_backend: Optional[str] = None
    global_options: Dict[str, Any] = field(default_factory=dict)


class ConfigManager:
    """
    Plugin-based configuration manager.
    Each decompiler registers its own ConfigProvider.
    """
    
    CONFIG_DIR = Path.home() / ".ludi"
    CONFIG_FILE = CONFIG_DIR / "config.yaml"
    
    def __init__(self):
        self._config = LudiConfig()
        self._providers: Dict[str, ConfigProvider] = {}
        self._loaded = False
    
    def register_provider(self, provider: ConfigProvider):
        """Register a configuration provider for a backend."""
        self._providers[provider.backend_name] = provider
        
        # Immediately load env vars for this provider
        self._load_provider_from_env(provider)
        
        # Auto-discover if needed
        config = provider.get_config()
        if config.auto_discover and not config.path:
            if discovered_path := provider.auto_discover():
                config.path = discovered_path
                provider.set_config(config)
    
    def get_providers(self) -> List[ConfigProvider]:
        """Get all registered providers."""
        return list(self._providers.values())
    
    def load(self) -> LudiConfig:
        """Load configuration from all sources."""
        if self._loaded:
            return self._config
        
        # 1. Load from config file
        self._load_from_file()
        
        # 2. Override with environment variables
        self._load_from_env()
        
        # 3. Auto-discover if needed
        self._auto_discover_tools()
        
        self._loaded = True
        return self._config
    
    def _load_from_file(self):
        """Load configuration from YAML file."""
        if not self.CONFIG_FILE.exists():
            return
        
        try:
            with open(self.CONFIG_FILE, 'r') as f:
                data = yaml.safe_load(f) or {}
            
            # Load global config
            self._config.default_backend = data.get('default_backend')
            self._config.global_options = data.get('global_options', {})
            
            # Let each provider load its own config
            for provider in self._providers.values():
                if provider.backend_name in data:
                    backend_data = data[provider.backend_name]
                    config = BackendConfig(**backend_data)
                    provider.set_config(config)
            
        except Exception as e:
            print(f"Warning: Could not load config file: {e}")
    
    def _load_from_env(self):
        """Load configuration from environment variables."""
        # Global settings
        if default_backend := os.environ.get('LUDI_DEFAULT_BACKEND'):
            self._config.default_backend = default_backend
        
        # Let each provider handle its own environment variables
        for provider in self._providers.values():
            self._load_provider_from_env(provider)
    
    def _load_provider_from_env(self, provider: ConfigProvider):
        """Load environment variables for a specific provider."""
        # Standard env var pattern: LUDI_{BACKEND}_PATH, LUDI_{BACKEND}_ENABLED
        backend_upper = provider.backend_name.upper()
        
        config = provider.get_config()
        changed = False
        
        if path := os.environ.get(f'LUDI_{backend_upper}_PATH'):
            config.path = path
            changed = True
        
        if enabled := os.environ.get(f'LUDI_{backend_upper}_ENABLED'):
            config.enabled = enabled.lower() in ('true', '1', 'yes')
            changed = True
        
        if changed:
            provider.set_config(config)
    
    def _auto_discover_tools(self):
        """Auto-discover decompiler installations."""
        for provider in self._providers.values():
            config = provider.get_config()
            if config.auto_discover and not config.path:
                if discovered_path := provider.auto_discover():
                    config.path = discovered_path
                    provider.set_config(config)
    
    def save(self):
        """Save configuration to file."""
        # Create config directory if it doesn't exist
        self.CONFIG_DIR.mkdir(exist_ok=True)
        
        # Build config dict from all providers
        config_dict = {
            'default_backend': self._config.default_backend,
            'global_options': self._config.global_options
        }
        
        # Add each backend's config
        for provider in self._providers.values():
            backend_config = provider.get_config()
            config_dict[provider.backend_name] = {
                'path': backend_config.path,
                'enabled': backend_config.enabled,
                'auto_discover': backend_config.auto_discover,
                'options': backend_config.options
            }
        
        with open(self.CONFIG_FILE, 'w') as f:
            yaml.dump(config_dict, f, default_flow_style=False)
    
    def get_backend_config(self, backend: str) -> BackendConfig:
        """Get configuration for specific backend."""
        if not self._loaded:
            self.load()
        
        if backend not in self._providers:
            raise ValueError(f"No provider registered for backend: {backend}")
        
        return self._providers[backend].get_config()
    
    def set_backend_path(self, backend: str, path: str):
        """Set path for specific backend."""
        if not self._loaded:
            self.load()
        
        if backend not in self._providers:
            raise ValueError(f"No provider registered for backend: {backend}")
        
        config = self._providers[backend].get_config()
        config.path = path
        self._providers[backend].set_config(config)
    
    def get_available_backends(self) -> List[str]:
        """Get list of available and enabled backends."""
        if not self._loaded:
            self.load()
        
        available = []
        for provider in self._providers.values():
            if provider.is_available():
                available.append(provider.backend_name)
        
        return available
    
    def validate(self) -> Dict[str, bool]:
        """Validate configuration and return status for each backend."""
        if not self._loaded:
            self.load()
        
        return {
            provider.backend_name: provider.validate()
            for provider in self._providers.values()
        }


# Global config manager instance
_config_manager = None

def get_config_manager() -> ConfigManager:
    """Get global configuration manager instance."""
    global _config_manager
    if _config_manager is None:
        _config_manager = ConfigManager()
    return _config_manager