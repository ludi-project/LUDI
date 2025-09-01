from abc import ABC, abstractmethod
from typing import TYPE_CHECKING, Optional

if TYPE_CHECKING:
    from .query import (
        FunctionCollection,
        SymbolCollection,
        VariableCollection,
        XRefCollection,
    )
    from .types import (
        BasicBlock,
        CFG,
        CallGraph,
        Function,
        Instruction,
        Symbol,
        Type,
        Variable,
        XRef,
    )


class FunctionManager(ABC):
    @abstractmethod
    def all(self, level: Optional[str] = None) -> list["Function"]:
        pass

    def __iter__(self):
        return iter(self.all())

    def __len__(self):
        return len(self.all())

    def __getitem__(self, index):
        return self.all()[index]

    @abstractmethod
    def by_address(
        self, addr: int, level: Optional[str] = None
    ) -> Optional["Function"]:
        pass

    @abstractmethod
    def containing(
        self, addr: int, level: Optional[str] = None
    ) -> Optional["Function"]:
        pass

    def function_containing(
        self, addr: int, level: Optional[str] = None
    ) -> Optional["Function"]:
        """Alias for containing() to match the naming pattern used in types.py"""
        return self.containing(addr, level)

    @abstractmethod
    def decompiled_code(self, addr: int, level: Optional[str] = None) -> Optional[str]:
        pass

    @abstractmethod
    def by_name(self, name: str) -> Optional["Function"]:
        pass

    @abstractmethod
    def basic_blocks(
        self, addr: int, level: Optional[str] = None
    ) -> list["BasicBlock"]:
        pass

    @abstractmethod
    def instructions(
        self, addr: int, level: Optional[str] = None
    ) -> list["Instruction"]:
        pass

    @abstractmethod
    def available_levels(self) -> list[str]:
        pass

    @abstractmethod
    def cfg(self, addr: int) -> Optional["CFG"]:
        pass

    @abstractmethod
    def call_graph(self) -> Optional["CallGraph"]:
        pass

    @abstractmethod
    def representation(self, addr: int, level: str = "disasm") -> Optional[str]:
        pass

    @abstractmethod
    def string_references(self, addr: int) -> list[tuple]:
        pass

    @property
    def functions(self) -> "FunctionCollection":
        from .query import FunctionCollection

        return FunctionCollection(self.all)


class SymbolManager(ABC):
    @abstractmethod
    def all(self) -> list["Symbol"]:
        pass

    def __iter__(self):
        return iter(self.all())

    def __len__(self):
        return len(self.all())

    def __getitem__(self, index):
        return self.all()[index]

    @abstractmethod
    def by_address(self, addr: int) -> Optional["Symbol"]:
        pass

    @abstractmethod
    def by_name(self, name: str) -> Optional["Symbol"]:
        pass

    @abstractmethod
    def strings(self) -> list["Symbol"]:
        pass

    @property
    def symbols(self) -> "SymbolCollection":
        from .query import SymbolCollection

        return SymbolCollection(self.all)


class VariableManager(ABC):
    @abstractmethod
    def all(self, scope: Optional[int] = None) -> list["Variable"]:
        pass

    def __iter__(self):
        return iter(self.all())

    def __len__(self):
        return len(self.all())

    def __getitem__(self, index):
        return self.all()[index]

    @abstractmethod
    def types(self) -> list["Type"]:
        pass

    @property
    def variables(self) -> "VariableCollection":
        from .query import VariableCollection

        return VariableCollection(lambda: self.all())


class XRefManager(ABC):
    @abstractmethod
    def xrefs_to(self, addr: int) -> list["XRef"]:
        pass

    @abstractmethod
    def xrefs_from(self, addr: int) -> list["XRef"]:
        pass

    @abstractmethod
    def all(self) -> list["XRef"]:
        pass

    def __iter__(self):
        return iter(self.all())

    def __len__(self):
        return len(self.all())

    def __getitem__(self, index):
        return self.all()[index]

    @abstractmethod
    def call_graph(self) -> dict:
        pass

    @abstractmethod
    def data_flow(self, addr: int) -> dict:
        pass

    def function_xrefs(self, func_addr: int) -> dict:
        return {
            "calls_to": self.xrefs_to(func_addr),
            "calls_from": self.xrefs_from(func_addr),
        }

    @property
    def xrefs(self) -> "XRefCollection":
        from .query import XRefCollection

        return XRefCollection(self.get_all_xrefs)


class BinaryManager(ABC):
    @abstractmethod
    def segments(self) -> list[dict]:
        pass

    @abstractmethod
    def sections(self) -> list[dict]:
        pass

    @abstractmethod
    def imports(self) -> list["Symbol"]:
        pass

    @abstractmethod
    def exports(self) -> list["Symbol"]:
        pass

    @abstractmethod
    def entry_points(self) -> list[int]:
        pass

    @property
    @abstractmethod
    def file_info(self) -> dict:
        pass

    @abstractmethod
    def strings(self) -> list["Symbol"]:
        pass

    @abstractmethod
    def search_strings(self, pattern: str) -> list["Symbol"]:
        pass


class TypeManager(ABC):
    @abstractmethod
    def all(self) -> list["Type"]:
        pass

    def __iter__(self):
        return iter(self.all())

    def __len__(self):
        return len(self.all())

    def __getitem__(self, index):
        return self.all()[index]

    @abstractmethod
    def by_name(self, name: str) -> Optional["Type"]:
        pass

    @abstractmethod
    def function_signature(self, addr: int) -> Optional["Type"]:
        pass

    @abstractmethod
    def primitive_types(self) -> list["Type"]:
        pass

    @abstractmethod
    def user_types(self) -> list["Type"]:
        pass


class ArchitectureManager(ABC):
    @property
    @abstractmethod
    def name(self) -> str:
        pass

    @property
    @abstractmethod
    def bits(self) -> int:
        pass

    @property
    @abstractmethod
    def endian(self) -> str:
        pass

    @abstractmethod
    def registers(self) -> list[str]:
        pass

    @abstractmethod
    def get_register_info(self, name: str) -> Optional[dict]:
        pass

    @abstractmethod
    def calling_convention(self) -> Optional[str]:
        pass


class MemoryManager(ABC):
    @property
    @abstractmethod
    def base_address(self) -> int:
        pass

    @abstractmethod
    def read(self, addr: int, size: int) -> Optional[bytes]:
        pass

    @abstractmethod
    def read_string(self, addr: int, max_length: int = 1024) -> Optional[str]:
        pass

    @abstractmethod
    def read_pointer(self, addr: int) -> Optional[int]:
        pass

    @abstractmethod
    def is_valid_address(self, addr: int) -> bool:
        pass

    @abstractmethod
    def permissions(self, addr: int) -> Optional[str]:
        pass
