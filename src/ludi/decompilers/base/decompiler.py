from abc import ABC, abstractmethod
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .managers import FunctionManager, XRefManager, SymbolManager, BinaryManager


class DecompilerBase(ABC):
    """Base class for all decompiler adapters."""
    
    def __init__(self, binary_path: str, **kwargs):
        self.binary_path = binary_path
        self._function_manager = None
        self._xref_manager = None
        self._symbol_manager = None
        self._binary_manager = None
    
    @property
    @abstractmethod
    def functions(self) -> "FunctionManager":
        """Get the function manager for this decompiler."""
        pass
    
    @property
    @abstractmethod
    def xrefs(self) -> "XRefManager":
        """Get the cross-reference manager for this decompiler."""
        pass
    
    @property
    @abstractmethod
    def symbols(self) -> "SymbolManager":
        """Get the symbol manager for this decompiler."""
        pass
    
    @property
    @abstractmethod
    def binary(self) -> "BinaryManager":
        """Get the binary manager for this decompiler."""
        pass