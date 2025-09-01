from abc import ABC, abstractmethod
from typing import TYPE_CHECKING, List, Optional

if TYPE_CHECKING:
    from .query import FunctionCollection, SymbolCollection, VariableCollection, XRefCollection
    from .types import BasicBlock, Function, Instruction, Symbol, Type, Variable, XRef


class FunctionManager(ABC):
    @abstractmethod
    def get_all(self, level: Optional[str] = None) -> List["Function"]:
        pass

    def __iter__(self):
        return iter(self.get_all())

    def __len__(self):
        return len(self.get_all())

    def __getitem__(self, index):
        return self.get_all()[index]

    @abstractmethod
    def get_by_address(self, addr: int, level: Optional[str] = None) -> Optional["Function"]:
        pass

    @abstractmethod
    def get_function_containing(
        self, addr: int, level: Optional[str] = None
    ) -> Optional["Function"]:
        pass

    @abstractmethod
    def get_decompiled_code(self, addr: int, level: Optional[str] = None) -> Optional[str]:
        pass

    @abstractmethod
    def get_by_name(self, name: str) -> Optional["Function"]:
        pass

    @abstractmethod
    def get_basic_blocks(self, addr: int, level: Optional[str] = None) -> List["BasicBlock"]:
        pass

    @abstractmethod
    def get_instructions(self, addr: int, level: Optional[str] = None) -> List["Instruction"]:
        pass

    @abstractmethod
    def get_available_levels(self) -> List[str]:
        pass

    @abstractmethod
    def get_cfg(self, addr: int) -> Optional["CFG"]:
        pass

    @abstractmethod
    def get_call_graph(self) -> Optional["CallGraph"]:
        pass

    @abstractmethod
    def get_representation(self, addr: int, level: str = "disasm") -> Optional[str]:
        pass

    @abstractmethod
    def get_string_references(self, addr: int) -> List[tuple]:
        pass

    @property
    def functions(self) -> "FunctionCollection":
        from .query import FunctionCollection

        return FunctionCollection(self.get_all)


class SymbolManager(ABC):
    @abstractmethod
    def get_all(self) -> List["Symbol"]:
        pass

    def __iter__(self):
        return iter(self.get_all())

    def __len__(self):
        return len(self.get_all())

    def __getitem__(self, index):
        return self.get_all()[index]

    @abstractmethod
    def get_by_address(self, addr: int) -> Optional["Symbol"]:
        pass

    @abstractmethod
    def get_by_name(self, name: str) -> Optional["Symbol"]:
        pass

    @abstractmethod
    def get_variables(self, scope: Optional[int] = None) -> List["Variable"]:
        pass

    @abstractmethod
    def get_types(self) -> List["Type"]:
        pass

    @abstractmethod
    def get_strings(self) -> List["Symbol"]:
        pass

    @property
    def symbols(self) -> "SymbolCollection":
        from .query import SymbolCollection

        return SymbolCollection(self.get_all)

    @property
    def variables(self) -> "VariableCollection":
        from .query import VariableCollection

        return VariableCollection(lambda: self.get_variables())


class XRefManager(ABC):
    @abstractmethod
    def get_xrefs_to(self, addr: int) -> List["XRef"]:
        pass

    @abstractmethod
    def get_xrefs_from(self, addr: int) -> List["XRef"]:
        pass

    @abstractmethod
    def get_all_xrefs(self) -> List["XRef"]:
        pass

    def __iter__(self):
        return iter(self.get_all_xrefs())

    def __len__(self):
        return len(self.get_all_xrefs())

    def __getitem__(self, index):
        return self.get_all_xrefs()[index]

    @abstractmethod
    def get_call_graph(self) -> dict:
        pass

    @abstractmethod
    def get_data_flow(self, addr: int) -> dict:
        pass

    def get_function_xrefs(self, func_addr: int) -> dict:
        return {
            "calls_to": self.get_xrefs_to(func_addr),
            "calls_from": self.get_xrefs_from(func_addr),
        }

    @property
    def xrefs(self) -> "XRefCollection":
        from .query import XRefCollection

        return XRefCollection(self.get_all_xrefs)


class BinaryManager(ABC):
    @abstractmethod
    def get_segments(self) -> List[dict]:
        pass

    @abstractmethod
    def get_sections(self) -> List[dict]:
        pass

    @abstractmethod
    def get_imports(self) -> List["Symbol"]:
        pass

    @abstractmethod
    def get_exports(self) -> List["Symbol"]:
        pass

    @abstractmethod
    def get_entry_points(self) -> List[int]:
        pass

    @abstractmethod
    def get_file_info(self) -> dict:
        pass

    @abstractmethod
    def get_strings(self) -> List["Symbol"]:
        pass

    @abstractmethod
    def search_strings(self, pattern: str) -> List["Symbol"]:
        pass


class TypeManager(ABC):
    @abstractmethod
    def get_all(self) -> List["Type"]:
        pass

    def __iter__(self):
        return iter(self.get_all())

    def __len__(self):
        return len(self.get_all())

    def __getitem__(self, index):
        return self.get_all()[index]

    @abstractmethod
    def get_by_name(self, name: str) -> Optional["Type"]:
        pass

    @abstractmethod
    def get_function_signature(self, addr: int) -> Optional["Type"]:
        pass

    @abstractmethod
    def get_primitive_types(self) -> List["Type"]:
        pass

    @abstractmethod
    def get_user_types(self) -> List["Type"]:
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
    def get_registers(self) -> List[str]:
        pass

    @abstractmethod
    def get_register_info(self, name: str) -> Optional[dict]:
        pass

    @abstractmethod
    def get_calling_convention(self) -> Optional[str]:
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
    def get_permissions(self, addr: int) -> Optional[str]:
        pass
