from abc import ABC, abstractmethod
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .managers import (
        ArchitectureManager,
        BinaryManager,
        FunctionManager,
        MemoryManager,
        SymbolManager,
        TypeManager,
        XRefManager,
    )


class DecompilerBase(ABC):
    def __init__(self, binary_path: str, **kwargs):
        self.binary_path = binary_path

    @property
    @abstractmethod
    def backend_name(self) -> str:
        pass

    def close(self) -> None:
        pass

    def __enter__(self) -> "DecompilerBase":
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        self.close()

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
