"""Ghidra configuration management."""

import os
import shutil
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from ..base.config import ConfigProvider, BackendConfig, get_config_manager


@dataclass
class GhidraConfig:
    """Ghidra configuration."""
    path: Optional[str] = None
    project_location: Optional[str] = None
    headless_path: Optional[str] = None


class GhidraConfigProvider(ConfigProvider):
    """Ghidra-specific configuration provider."""
    
    def __init__(self):
        self._config = BackendConfig()
    
    @property
    def backend_name(self) -> str:
        return "ghidra"
    
    def get_config(self) -> BackendConfig:
        return self._config
    
    def set_config(self, config: BackendConfig) -> None:
        self._config = config
    
    def auto_discover(self) -> Optional[str]:
        """Auto-discover Ghidra installation."""
        # First check environment variables (what pyhidra uses)
        ghidra_install_dir = os.environ.get('GHIDRA_INSTALL_DIR')
        if ghidra_install_dir and os.path.exists(ghidra_install_dir):
            # Validate this is a proper Ghidra installation
            if self.validate(ghidra_install_dir):
                return ghidra_install_dir
        
        # Check if pyhidra is available (indicates Ghidra setup)
        try:
            import pyhidra
            # pyhidra is available but no GHIDRA_INSTALL_DIR set
            # This means Ghidra is accessible but we don't know the path
            # Let's try other environment variables
            for env_var in ['GHIDRA_HOME', 'GHIDRA_ROOT']:
                ghidra_dir = os.environ.get(env_var)
                if ghidra_dir and os.path.exists(ghidra_dir):
                    if self.validate(ghidra_dir):
                        return ghidra_dir
        except ImportError:
            pass
        
        # Then check for analyzeHeadless script
        headless_scripts = ['analyzeHeadless', 'analyzeHeadless.bat']
        
        # Check PATH first - if script is in PATH, try to find installation
        for script_name in headless_scripts:
            if script_path := shutil.which(script_name):
                # Try to find the Ghidra installation directory from script path
                script_path_obj = Path(script_path)
                # Look for parent directory that looks like Ghidra installation
                for parent in script_path_obj.parents:
                    if parent.name.lower().startswith('ghidra') and self.validate(str(parent)):
                        return str(parent)
        
        # Check common installation paths
        common_paths = [
            # Linux/macOS common locations
            '/opt/ghidra*',
            '/usr/local/ghidra*',
            '/home/*/ghidra*',
            '/Applications/ghidra*',
            '~/ghidra*',
            # Windows common locations
            'C:\\Program Files\\ghidra*',
            'C:\\ghidra*',
        ]
        
        for pattern in common_paths:
            paths = self._glob_paths(pattern)
            for path in paths:
                if path.is_dir() and self.validate(str(path)):
                    return str(path)
        
        return None
    
    def validate(self, path: Optional[str] = None) -> bool:
        """Validate Ghidra installation."""
        if path is None:
            path = self._config.path
        
        if not path:
            return False
        
        ghidra_path = Path(path)
        
        # Check if it's a directory (Ghidra installation root)
        if ghidra_path.is_dir():
            # Look for analyzeHeadless script in support directory
            headless_script = ghidra_path / 'support' / 'analyzeHeadless'
            headless_bat = ghidra_path / 'support' / 'analyzeHeadless.bat'
            return headless_script.exists() or headless_bat.exists()
        
        # Check if it's the analyzeHeadless script itself
        elif ghidra_path.is_file():
            name = ghidra_path.name.lower()
            return 'analyzeheadless' in name
        
        return False
    
    def _glob_paths(self, pattern: str) -> list[Path]:
        """Expand glob pattern and return existing paths."""
        try:
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


def get_ghidra_config() -> GhidraConfig:
    """Get Ghidra configuration from environment."""
    ghidra_path = os.environ.get('LUDI_GHIDRA_PATH')
    project_location = os.environ.get('LUDI_GHIDRA_PROJECT_LOCATION', '/tmp/ludi_ghidra_projects')
    
    # Try to find analyzeHeadless script
    headless_path = None
    if ghidra_path:
        # Try common locations for analyzeHeadless
        potential_paths = [
            os.path.join(ghidra_path, 'support', 'analyzeHeadless'),
            os.path.join(ghidra_path, 'support', 'analyzeHeadless.bat'),
            os.path.join(ghidra_path, 'analyzeHeadless'),
            os.path.join(ghidra_path, 'analyzeHeadless.bat'),
        ]
        
        for path in potential_paths:
            if os.path.exists(path):
                headless_path = path
                break
    
    return GhidraConfig(
        path=ghidra_path,
        project_location=project_location,
        headless_path=headless_path
    )


# Auto-register ghidra provider when this module is imported
_ghidra_provider = GhidraConfigProvider()
get_config_manager().register_provider(_ghidra_provider)