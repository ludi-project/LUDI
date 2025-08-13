"""
Decompiler modules with auto-discovery and registration.

This module automatically discovers and registers all available decompiler backends.
Each backend is responsible for registering itself when imported.
"""

# Import all decompiler backends to trigger auto-registration
# Each backend registers its ConfigProvider when imported

# IDA backend
try:
    from . import ida
    __all__ = ["ida"]
except ImportError:
    __all__ = []

# Ghidra backend
try:
    from . import ghidra
    __all__.append("ghidra")
except ImportError:
    pass

# angr backend
try:
    from . import angr
    __all__.append("angr")
except ImportError:
    pass

# Export base classes for new backend development
from .base import (
    DecompilerBase, 
    FunctionManager, XRefManager, SymbolManager,
    Function, BasicBlock, XRef, Symbol,
    ConfigProvider, BackendConfig, get_config_manager
)

__all__ += [
    "DecompilerBase", 
    "FunctionManager", "XRefManager", "SymbolManager",
    "Function", "BasicBlock", "XRef", "Symbol",
    "ConfigProvider", "BackendConfig", "get_config_manager"
]