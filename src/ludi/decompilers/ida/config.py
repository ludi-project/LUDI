import shutil
from pathlib import Path
from typing import Optional

from ..base.config import ConfigProvider, BackendConfig, get_config_manager


class IdaConfigProvider(ConfigProvider):
    """IDA-specific configuration provider."""
    
    def __init__(self):
        self._config = BackendConfig()
    
    @property
    def backend_name(self) -> str:
        return "ida"
    
    def get_config(self) -> BackendConfig:
        return self._config
    
    def set_config(self, config: BackendConfig) -> None:
        self._config = config
    
    def auto_discover(self) -> Optional[str]:
        """Auto-discover IDA installation."""
        # Common IDA executable names
        ida_executables = ['idat64', 'idat', 'ida64', 'ida']
        
        # First check PATH
        for exe_name in ida_executables:
            if binary_path := shutil.which(exe_name):
                if self.validate(binary_path):
                    # Resolve symlinks to find the actual installation
                    real_binary_path = Path(binary_path).resolve()
                    # Look for parent directories that look like IDA installations
                    for parent in [real_binary_path.parent] + list(real_binary_path.parents):
                        if self._looks_like_ida_installation(parent):
                            return str(parent)
                    # Fallback to the directory containing the binary
                    return str(real_binary_path.parent)
        
        # Then check common installation paths
        common_paths = [
            # Windows
            "C:\\Program Files\\IDA Pro*",
            "C:\\Program Files (x86)\\IDA Pro*",
            # macOS
            "/Applications/IDA Pro*",
            # Linux common locations
            "/opt/ida*",
            "/usr/local/ida*",
            "/home/*/ida*",
            "~/ida*",
        ]
        
        for pattern in common_paths:
            paths = self._glob_paths(pattern)
            for path in paths:
                if path.is_dir():
                    # Look for IDA executables in this directory
                    for exe_name in ida_executables:
                        exe_path = path / exe_name
                        if exe_path.exists() and self.validate(str(exe_path)):
                            return str(path)
        
        # Special case: if binary is in ~/bin, look for IDA installation elsewhere
        for pattern in ["~/bin/idat64", "/home/*/bin/idat64"]:
            paths = self._glob_paths(pattern)
            for binary_path in paths:
                if binary_path.exists() and self.validate(str(binary_path)):
                    # This might be a symlink or standalone binary
                    # Return the directory containing it
                    return str(binary_path.parent)
        
        return None
    
    def validate(self, path: Optional[str] = None) -> bool:
        """Validate IDA installation."""
        if path is None:
            path = self._config.path
        
        if not path:
            return False
        
        ida_path = Path(path)
        
        # If it's a file, check if it's an IDA executable
        if ida_path.is_file():
            name = ida_path.name.lower()
            return any(ida_name in name for ida_name in ['idat', 'ida64', 'ida'])
        
        # If it's a directory, look for IDA executables inside
        elif ida_path.is_dir():
            ida_executables = ['idat64', 'idat', 'ida64', 'ida']
            for exe_name in ida_executables:
                exe_path = ida_path / exe_name
                if exe_path.exists():
                    return True
            return False
        
        return False
    
    def _looks_like_ida_installation(self, path: Path) -> bool:
        """Check if a directory looks like an IDA installation."""
        if not path.is_dir():
            return False
        
        # Check for typical IDA installation indicators
        ida_indicators = [
            # Common IDA files/directories
            'cfg', 'ids', 'sig', 'til', 'plugins',
            # IDA executables
            'idat64', 'idat', 'ida64', 'ida',
            # License files
            'license.txt', 'LICENSE'
        ]
        
        # Count how many indicators are present
        indicators_found = 0
        for indicator in ida_indicators:
            if (path / indicator).exists():
                indicators_found += 1
        
        # If we find multiple IDA-specific files/dirs, it's likely an IDA installation
        return indicators_found >= 3
    
    def _glob_paths(self, pattern: str) -> list[Path]:
        """Expand glob pattern and return existing paths."""
        try:
            import os
            
            # Handle tilde expansion
            if pattern.startswith('~'):
                pattern = os.path.expanduser(pattern)
            
            # Use pathlib for glob matching
            if '*' in pattern:
                # Extract the base directory and pattern
                parts = pattern.split('*')
                if len(parts) >= 2:
                    base = Path(parts[0]).parent
                    if base.exists():
                        return list(base.glob('*'.join(parts[1:])))
            else:
                # Direct path check
                path = Path(pattern)
                if path.exists():
                    return [path]
            
            return []
        except Exception:
            return []


# Auto-register IDA provider when this module is imported
_ida_provider = IdaConfigProvider()
get_config_manager().register_provider(_ida_provider)

# Export for external use
def get_ida_config() -> BackendConfig:
    """Get IDA configuration."""
    return _ida_provider.get_config()

