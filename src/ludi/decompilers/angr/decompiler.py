"""angr decompiler implementation."""

from __future__ import annotations

from typing import Optional

from ..base import DecompilerBase, FunctionManager, XRefManager, SymbolManager, BinaryManager
from .config import get_angr_config
from .managers import AngrFunctionManager, AngrXRefManager, AngrSymbolManager, AngrBinaryManager


class AngrNative:
    """Native angr interface."""
    
    def __init__(self, binary_path: str, **kwargs):
        self.binary_path = binary_path
        self.config = get_angr_config()
        
        # Import angr here to fail gracefully if not installed
        try:
            import angr
            self.angr_module = angr
        except ImportError:
            raise RuntimeError("angr is not installed. Install with: pip install angr")
        
        # Create angr project
        self.project = self._create_project(**kwargs)
    
    def _create_project(self, **kwargs):
        """Create angr project with configuration."""
        project_kwargs = {
            'auto_load_libs': self.config.auto_load_libs,
            'use_sim_procedures': self.config.use_sim_procedures,
            'load_debug_info': self.config.load_debug_info
        }
        
        # Override with user-provided kwargs
        project_kwargs.update(kwargs)
        
        try:
            return self.angr_module.Project(self.binary_path, **project_kwargs)
        except Exception as e:
            raise RuntimeError(f"Failed to create angr project: {e}")
    
    def __getattr__(self, name):
        """Delegate attribute access to angr project."""
        return getattr(self.project, name)


class Angr(DecompilerBase):
    """angr decompiler implementation."""
    
    def __init__(self, binary_path: str, **kwargs):
        super().__init__(binary_path, **kwargs)
        
        self.native = AngrNative(binary_path, **kwargs)
        
        # Initialize managers
        self._function_manager = AngrFunctionManager(self.native, self)
        self._xref_manager = AngrXRefManager(self.native, self)
        self._symbol_manager = AngrSymbolManager(self.native, self)
        self._binary_manager = AngrBinaryManager(self.native, self)
    
    @property
    def functions(self) -> FunctionManager:
        """Get the function manager for this decompiler."""
        return self._function_manager
    
    @property
    def xrefs(self) -> XRefManager:
        """Get the cross-reference manager for this decompiler."""
        return self._xref_manager
    
    @property
    def symbols(self) -> SymbolManager:
        """Get the symbol manager for this decompiler."""
        return self._symbol_manager
    
    @property
    def binary(self) -> BinaryManager:
        """Get the binary manager for this decompiler."""
        return self._binary_manager