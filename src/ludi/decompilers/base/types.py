from dataclasses import dataclass
from typing import Optional, List, Dict, Any, TYPE_CHECKING

if TYPE_CHECKING:
    from .managers import FunctionManager, SymbolManager, XRefManager


@dataclass
class Function:
    """Function representation at different abstraction levels."""
    start: int
    end: int
    name: Optional[str] = None
    size: Optional[int] = None
    level: str = "disassembly"  # representation level
    _manager: Optional["FunctionManager"] = None
    _native: Optional[Any] = None
    
    def __post_init__(self):
        if self.size is None:
            self.size = self.end - self.start
    
    @property
    def native(self) -> Optional[Any]:
        """Access to native decompiler function object."""
        return self._native
    
    def get_decompiled_code(self, level: Optional[str] = None) -> Optional[str]:
        """Get decompiled code for this function."""
        if self._manager:
            return self._manager.get_decompiled_code(self.start, level)
        return None
    
    def get_variables(self) -> List["Variable"]:
        """Get variables in this function."""
        if self._manager and hasattr(self._manager, '_analyzer'):
            return self._manager._analyzer.symbols.get_variables(self.start)
        return []
    
    def get_xrefs_to(self) -> List["XRef"]:
        """Get cross-references to this function."""
        if self._manager and hasattr(self._manager, '_analyzer'):
            return self._manager._analyzer.xrefs.get_xrefs_to(self.start)
        return []
    
    def get_xrefs_from(self) -> List["XRef"]:
        """Get cross-references from this function."""
        if self._manager and hasattr(self._manager, '_analyzer'):
            xrefs = []
            for ea in range(self.start, self.end):
                xrefs.extend(self._manager._analyzer.xrefs.get_xrefs_from(ea))
            return xrefs
        return []
    
    def get_callers(self) -> List["Function"]:
        """Get functions that call this function."""
        callers = []
        for xref in self.get_xrefs_to():
            if xref.xref_type == "call" and self._manager:
                caller = self._manager.get_function_containing(xref.from_addr)
                if caller and caller.start != self.start:
                    callers.append(caller)
        return callers
    
    def get_callees(self) -> List["Function"]:
        """Get functions called by this function."""
        callees = []
        for xref in self.get_xrefs_from():
            if xref.xref_type == "call" and self._manager:
                callee = self._manager.get_function_containing(xref.to_addr)
                if callee and callee.start != self.start:
                    callees.append(callee)
        return callees
    
    def get_basic_blocks(self, level: Optional[str] = None) -> List["BasicBlock"]:
        """Get basic blocks for this function."""
        if self._manager:
            blocks = self._manager.get_basic_blocks(self.start, level)
            # Set function reference on each block
            for block in blocks:
                block._function = self
                # Set function reference on each instruction in the block
                for instr in block.instructions:
                    instr._function = self
                    instr._basic_block = block
            return blocks
        return []
    
    def get_instructions(self, level: Optional[str] = None) -> List["Instruction"]:
        """Get instructions for this function."""
        if self._manager:
            instructions = self._manager.get_instructions(self.start, level)
            # Set function reference on each instruction
            for instr in instructions:
                instr._function = self
            return instructions
        return []
    
    def get_instruction_at(self, addr: int) -> Optional["Instruction"]:
        """Get instruction at specific address within this function."""
        if not (self.start <= addr < self.end):
            return None
        for instr in self.get_instructions():
            if instr.address == addr:
                return instr
        return None
    
    def to_dict(self) -> Dict[str, Any]:
        """Export as dict."""
        return {
            "start": hex(self.start),
            "end": hex(self.end),
            "name": self.name,
            "size": self.size,
            "level": self.level
        }


@dataclass
class Instruction:
    """Instruction representation."""
    address: int
    mnemonic: str
    operands: List[str]
    bytes: Optional[bytes] = None
    level: str = "disassembly"
    _native: Optional[Any] = None
    _basic_block: Optional["BasicBlock"] = None  # Reference to containing basic block
    _function: Optional["Function"] = None  # Reference to containing function
    
    @property
    def native(self) -> Optional[Any]:
        """Access to native decompiler instruction object."""
        return self._native
    
    def get_function(self) -> Optional["Function"]:
        """Get the function that contains this instruction."""
        if self._function:
            return self._function
        if self._basic_block:
            return self._basic_block.get_function()
        return None
    
    def get_basic_block(self) -> Optional["BasicBlock"]:
        """Get the basic block that contains this instruction."""
        return self._basic_block
    
    def to_dict(self) -> Dict[str, Any]:
        """Export as dict."""
        return {
            "address": hex(self.address),
            "mnemonic": self.mnemonic,
            "operands": self.operands,
            "level": self.level
        }


@dataclass
class Variable:
    """Variable representation."""
    name: str
    var_type: str
    scope: Optional[int] = None  # function address for locals
    size: Optional[int] = None
    _manager: Optional["SymbolManager"] = None
    _native: Optional[Any] = None
    
    @property
    def native(self) -> Optional[Any]:
        """Access to native decompiler variable object."""
        return self._native
    
    def get_xrefs(self) -> List["XRef"]:
        """Get cross-references to this variable (if it has an address)."""
        if self._manager and hasattr(self._manager, '_analyzer') and self.scope:
            # Variables don't always have direct addresses, this is a placeholder
            return []
        return []
    
    def to_dict(self) -> Dict[str, Any]:
        """Export as dict."""
        return {
            "name": self.name,
            "type": self.var_type,
            "scope": hex(self.scope) if self.scope else None,
            "size": self.size
        }


@dataclass
class Type:
    """Type information."""
    name: str
    size: int
    kind: str  # "struct", "union", "enum", "primitive", etc.
    _native: Optional[Any] = None
    
    @property
    def native(self) -> Optional[Any]:
        """Access to native decompiler type object."""
        return self._native
    
    def to_dict(self) -> Dict[str, Any]:
        """Export as dict."""
        return {
            "name": self.name,
            "size": self.size,
            "kind": self.kind
        }


@dataclass
class BasicBlock:
    """Basic block representation."""
    start: int
    end: int
    instructions: List["Instruction"]  # Changed from instruction_addrs to actual Instruction objects
    size: Optional[int] = None
    level: str = "disassembly"
    _native: Optional[Any] = None
    _function: Optional["Function"] = None  # Reference to containing function
    
    def __post_init__(self):
        if self.size is None:
            self.size = self.end - self.start
    
    @property
    def native(self) -> Optional[Any]:
        """Access to native decompiler basic block object."""
        return self._native
    
    @property
    def instruction_addrs(self) -> List[int]:
        """Get instruction addresses (for backward compatibility)."""
        return [instr.address for instr in self.instructions]
    
    def get_function(self) -> Optional["Function"]:
        """Get the function that contains this basic block."""
        return self._function
    
    def get_instruction_at(self, addr: int) -> Optional["Instruction"]:
        """Get instruction at specific address within this block."""
        if not (self.start <= addr < self.end):
            return None
        for instr in self.instructions:
            if instr.address == addr:
                return instr
        return None
    
    def to_dict(self) -> Dict[str, Any]:
        """Export as dict."""
        return {
            "start": hex(self.start),
            "end": hex(self.end),
            "size": self.size,
            "instruction_count": len(self.instruction_addrs),
            "level": self.level
        }


@dataclass
class XRef:
    """Cross-reference representation."""
    from_addr: int
    to_addr: int
    xref_type: str
    _manager: Optional["XRefManager"] = None
    _native: Optional[Any] = None
    
    @property
    def native(self) -> Optional[Any]:
        """Access to native decompiler xref object."""
        return self._native
    
    def get_from_function(self) -> Optional["Function"]:
        """Get function containing the from_addr."""
        if self._manager and hasattr(self._manager, '_analyzer'):
            return self._manager._analyzer.functions.get_function_containing(self.from_addr)
        return None
    
    def get_to_function(self) -> Optional["Function"]:
        """Get function containing the to_addr (if applicable)."""
        if self._manager and hasattr(self._manager, '_analyzer'):
            return self._manager._analyzer.functions.get_function_containing(self.to_addr)
        return None
    
    def to_dict(self) -> Dict[str, Any]:
        """Export as dict."""
        return {
            "from_addr": hex(self.from_addr),
            "to_addr": hex(self.to_addr),
            "xref_type": self.xref_type
        }


@dataclass
class Symbol:
    """Symbol representation."""
    address: int
    name: str
    symbol_type: str
    size: Optional[int] = None
    _manager: Optional["SymbolManager"] = None
    _native: Optional[Any] = None
    
    @property
    def native(self) -> Optional[Any]:
        """Access to native decompiler symbol object."""
        return self._native
    
    def get_xrefs_to(self) -> List["XRef"]:
        """Get cross-references to this symbol."""
        if self._manager and hasattr(self._manager, '_analyzer'):
            return self._manager._analyzer.xrefs.get_xrefs_to(self.address)
        return []
    
    def get_xrefs_from(self) -> List["XRef"]:
        """Get cross-references from this symbol."""
        if self._manager and hasattr(self._manager, '_analyzer'):
            return self._manager._analyzer.xrefs.get_xrefs_from(self.address)
        return []
    
    def to_dict(self) -> Dict[str, Any]:
        """Export as dict."""
        return {
            "address": hex(self.address),
            "name": self.name,
            "symbol_type": self.symbol_type,
            "size": self.size
        }