from abc import ABC, abstractmethod
from typing import List, Optional, TYPE_CHECKING

if TYPE_CHECKING:
    from .types import Function, BasicBlock, XRef, Symbol, Instruction, Variable, Type
    from .query import FunctionCollection, SymbolCollection, XRefCollection, VariableCollection


class FunctionManager(ABC):
    """Function management - clean and modular."""

    @abstractmethod
    def get_all(self, level: Optional[str] = None) -> List["Function"]:
        """Get functions, optionally at specific representation level."""
        pass
    
    # Make manager directly iterable
    def __iter__(self):
        """Iterate over functions directly."""
        return iter(self.get_all())
    
    def __len__(self):
        """Get function count."""
        return len(self.get_all())
    
    def __getitem__(self, index):
        """Get function by index."""
        return self.get_all()[index]
    
    @abstractmethod  
    def get_by_address(self, addr: int, level: Optional[str] = None) -> Optional["Function"]:
        """Get function at address, optionally at specific level."""
        pass
    
    @abstractmethod
    def get_function_containing(self, addr: int, level: Optional[str] = None) -> Optional["Function"]:
        """Get function that contains the given address."""
        pass
    
    @abstractmethod
    def get_decompiled_code(self, addr: int, level: Optional[str] = None) -> Optional[str]:
        """Get decompiled code for function at address."""
        pass
    
    @abstractmethod
    def get_by_name(self, name: str) -> Optional["Function"]:
        """Get function by name."""
        pass
    
    @abstractmethod
    def get_basic_blocks(self, addr: int, level: Optional[str] = None) -> List["BasicBlock"]:
        """Get basic blocks for function."""
        pass
    
    @abstractmethod
    def get_instructions(self, addr: int, level: Optional[str] = None) -> List["Instruction"]:
        """Get instructions for function at specific level."""
        pass
    
    @abstractmethod
    def get_available_levels(self) -> List[str]:
        """Get available representation levels for this decompiler."""
        pass
    
    @property
    def functions(self) -> "FunctionCollection":
        """Get functions as collection."""
        from .query import FunctionCollection
        return FunctionCollection(self.get_all)


class SymbolManager(ABC):
    """Symbol and data management."""
    
    @abstractmethod
    def get_all(self) -> List["Symbol"]:
        """Get all symbols."""
        pass
    
    # Make manager directly iterable
    def __iter__(self):
        """Iterate over symbols directly."""
        return iter(self.get_all())
    
    def __len__(self):
        """Get symbol count."""
        return len(self.get_all())
    
    def __getitem__(self, index):
        """Get symbol by index."""
        return self.get_all()[index]
    
    @abstractmethod
    def get_by_address(self, addr: int) -> Optional["Symbol"]:
        """Get symbol by address."""
        pass
    
    @abstractmethod
    def get_by_name(self, name: str) -> Optional["Symbol"]:
        """Get symbol by name."""
        pass
    
    @abstractmethod
    def get_variables(self, scope: Optional[int] = None) -> List["Variable"]:
        """Get variables (optionally scoped to function)."""
        pass
    
    @abstractmethod
    def get_types(self) -> List["Type"]:
        """Get type information."""
        pass
    
    @abstractmethod
    def get_strings(self) -> List["Symbol"]:
        """Get string literals."""
        pass
    
    @property
    def symbols(self) -> "SymbolCollection":
        """Get symbols as collection."""
        from .query import SymbolCollection
        return SymbolCollection(self.get_all)
        
    @property
    def variables(self) -> "VariableCollection":
        """Get variables as collection."""
        from .query import VariableCollection
        return VariableCollection(lambda: self.get_variables())


class XRefManager(ABC):
    """XRef and flow analysis."""
    
    @abstractmethod
    def get_xrefs_to(self, addr: int) -> List["XRef"]:
        """Get cross-references to address."""
        pass
    
    @abstractmethod
    def get_xrefs_from(self, addr: int) -> List["XRef"]:
        """Get cross-references from address."""
        pass
    
    @abstractmethod
    def get_all_xrefs(self) -> List["XRef"]:
        """Get all cross-references."""
        pass
    
    # Make manager directly iterable
    def __iter__(self):
        """Iterate over all xrefs directly."""
        return iter(self.get_all_xrefs())
    
    def __len__(self):
        """Get xref count."""
        return len(self.get_all_xrefs())
    
    def __getitem__(self, index):
        """Get xref by index."""
        return self.get_all_xrefs()[index]
    
    @abstractmethod
    def get_call_graph(self) -> dict:
        """Get call graph data."""
        pass
    
    @abstractmethod
    def get_data_flow(self, addr: int) -> dict:
        """Get data flow information."""
        pass
    
    def get_function_xrefs(self, func_addr: int) -> dict:
        """Get all xrefs for a function (both to and from)."""
        return {
            'calls_to': self.get_xrefs_to(func_addr),
            'calls_from': self.get_xrefs_from(func_addr)
        }
    
    @property
    def xrefs(self) -> "XRefCollection":
        """Get xrefs as collection."""
        from .query import XRefCollection
        return XRefCollection(self.get_all_xrefs)


class BinaryManager(ABC):
    """Binary file format information."""
    
    @abstractmethod
    def get_segments(self) -> List[dict]:
        """Get memory segments."""
        pass
    
    @abstractmethod
    def get_sections(self) -> List[dict]:
        """Get file sections."""
        pass
    
    @abstractmethod
    def get_imports(self) -> List["Symbol"]:
        """Get imported functions/symbols."""
        pass
    
    @abstractmethod
    def get_exports(self) -> List["Symbol"]:
        """Get exported functions/symbols."""
        pass
    
    @abstractmethod
    def get_entry_points(self) -> List[int]:
        """Get program entry points."""
        pass
    
    @abstractmethod
    def get_file_info(self) -> dict:
        """Get file format information."""
        pass