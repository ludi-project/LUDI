from abc import ABC, abstractmethod
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .managers import ArchitectureManager, BinaryManager, FunctionManager, MemoryManager, SymbolManager, TypeManager, XRefManager


class DecompilerBase(ABC):
    def __init__(self, binary_path: str, **kwargs):
        self.binary_path = binary_path
        self._function_manager = None
        self._xref_manager = None
        self._symbol_manager = None
        self._binary_manager = None

    @property
    @abstractmethod
    def functions(self) -> "FunctionManager":
        pass

    @property
    @abstractmethod
    def xrefs(self) -> "XRefManager":
        pass

    @property
    @abstractmethod
    def symbols(self) -> "SymbolManager":
        pass

    @property
    @abstractmethod
    def binary(self) -> "BinaryManager":
        pass

    @property
    @abstractmethod
    def types(self) -> "TypeManager":
        pass

    @property
    @abstractmethod
    def architecture(self) -> "ArchitectureManager":
        pass

    @property
    @abstractmethod
    def memory(self) -> "MemoryManager":
        pass
