from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, Optional

if TYPE_CHECKING:
    from .managers import FunctionManager, SymbolManager, XRefManager


@dataclass
class Function:
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
        return self._native

    def decompiled_code(self, level: Optional[str] = None) -> Optional[str]:
        if self._manager:
            return self._manager.decompiled_code(self.start, level)
        return None

    def variables(self) -> list["Variable"]:
        if self._manager and hasattr(self._manager, "_analyzer"):
            return self._manager._analyzer.symbols.variables(self.start)
        return []

    def xrefs_to(self) -> list["XRef"]:
        if self._manager and hasattr(self._manager, "_analyzer"):
            return self._manager._analyzer.xrefs.xrefs_to(self.start)
        return []

    def xrefs_from(self) -> list["XRef"]:
        if self._manager and hasattr(self._manager, "_analyzer"):
            xrefs = []
            for ea in range(self.start, self.end):
                xrefs.extend(self._manager._analyzer.xrefs.xrefs_from(ea))
            return xrefs
        return []

    def callers(self) -> list["Function"]:
        callers = []
        for xref in self.xrefs_to():
            if xref.xref_type == "call" and self._manager:
                caller = self._manager.function_containing(xref.from_addr)
                if caller and caller.start != self.start:
                    callers.append(caller)
        return callers

    def callees(self) -> list["Function"]:
        callees = []
        for xref in self.xrefs_from():
            if xref.xref_type == "call" and self._manager:
                callee = self._manager.function_containing(xref.to_addr)
                if callee and callee.start != self.start:
                    callees.append(callee)
        return callees

    def basic_blocks(self, level: Optional[str] = None) -> list["BasicBlock"]:
        if self._manager:
            blocks = self._manager.basic_blocks(self.start, level)
            for block in blocks:
                block._function = self
                for instr in block.instructions:
                    instr._function = self
                    instr._basic_block = block
            return blocks
        return []

    def instructions(self, level: Optional[str] = None) -> list["Instruction"]:
        if self._manager:
            instructions = self._manager.instructions(self.start, level)
            for instr in instructions:
                instr._function = self
            return instructions
        return []

    def instruction_at(self, addr: int) -> Optional["Instruction"]:
        if not (self.start <= addr < self.end):
            return None
        for instr in self.instructions():
            if instr.address == addr:
                return instr
        return None

    def to_dict(self) -> dict[str, Any]:
        return {
            "start": hex(self.start),
            "end": hex(self.end),
            "name": self.name,
            "size": self.size,
            "level": self.level,
        }


@dataclass
class Instruction:
    address: int
    mnemonic: str
    operands: list[str]
    bytes: Optional[bytes] = None
    level: str = "disassembly"
    _native: Optional[Any] = None
    _basic_block: Optional["BasicBlock"] = None  # Reference to containing basic block
    _function: Optional["Function"] = None  # Reference to containing function

    @property
    def native(self) -> Optional[Any]:
        return self._native

    def function(self) -> Optional["Function"]:
        if self._function:
            return self._function
        if self._basic_block:
            return self._basic_block.function()
        return None

    def basic_block(self) -> Optional["BasicBlock"]:
        return self._basic_block

    def to_dict(self) -> dict[str, Any]:
        return {
            "address": hex(self.address),
            "mnemonic": self.mnemonic,
            "operands": self.operands,
            "level": self.level,
        }


@dataclass
class Variable:
    name: str
    var_type: str
    scope: Optional[int] = None  # function address for locals
    size: Optional[int] = None
    _manager: Optional["SymbolManager"] = None
    _native: Optional[Any] = None

    @property
    def native(self) -> Optional[Any]:
        return self._native

    def xrefs(self) -> list["XRef"]:
        if self._manager and hasattr(self._manager, "_analyzer") and self.scope:
            return []
        return []

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "type": self.var_type,
            "scope": hex(self.scope) if self.scope else None,
            "size": self.size,
        }


@dataclass
class Type:
    name: str
    size: int
    kind: str  # "struct", "union", "enum", "primitive", etc.
    _native: Optional[Any] = None

    @property
    def native(self) -> Optional[Any]:
        return self._native

    def to_dict(self) -> dict[str, Any]:
        return {"name": self.name, "size": self.size, "kind": self.kind}


@dataclass
class BasicBlock:
    start: int
    end: int
    instructions: list[
        "Instruction"
    ]  # Changed from instruction_addrs to actual Instruction objects
    size: Optional[int] = None
    level: str = "disassembly"
    _native: Optional[Any] = None
    _function: Optional["Function"] = None  # Reference to containing function

    def __post_init__(self):
        if self.size is None:
            self.size = self.end - self.start

    @property
    def native(self) -> Optional[Any]:
        return self._native

    @property
    def instruction_addrs(self) -> list[int]:
        return [instr.address for instr in self.instructions]

    def function(self) -> Optional["Function"]:
        return self._function

    def instruction_at(self, addr: int) -> Optional["Instruction"]:
        if not (self.start <= addr < self.end):
            return None
        for instr in self.instructions:
            if instr.address == addr:
                return instr
        return None

    def to_dict(self) -> dict[str, Any]:
        return {
            "start": hex(self.start),
            "end": hex(self.end),
            "size": self.size,
            "instruction_count": len(self.instruction_addrs),
            "level": self.level,
        }


@dataclass
class XRef:
    from_addr: int
    to_addr: int
    xref_type: str
    _manager: Optional["XRefManager"] = None
    _native: Optional[Any] = None

    @property
    def native(self) -> Optional[Any]:
        return self._native

    def from_function(self) -> Optional["Function"]:
        if self._manager and hasattr(self._manager, "_analyzer"):
            return self._manager._analyzer.functions.function_containing(self.from_addr)
        return None

    def to_function(self) -> Optional["Function"]:
        if self._manager and hasattr(self._manager, "_analyzer"):
            return self._manager._analyzer.functions.function_containing(self.to_addr)
        return None

    def to_dict(self) -> dict[str, Any]:
        return {
            "from_addr": hex(self.from_addr),
            "to_addr": hex(self.to_addr),
            "xref_type": self.xref_type,
        }


@dataclass
class CFG:
    function_addr: int
    basic_blocks: list["BasicBlock"]
    edges: list[tuple]  # (from_addr, to_addr)
    _manager: Optional["FunctionManager"] = None
    _native: Optional[Any] = None

    @property
    def native(self) -> Optional[Any]:
        return self._native

    def entry_block(self) -> Optional["BasicBlock"]:
        for block in self.basic_blocks:
            if block.start == self.function_addr:
                return block
        return None

    def to_dict(self) -> dict[str, Any]:
        return {
            "function_addr": hex(self.function_addr),
            "blocks": [block.to_dict() for block in self.basic_blocks],
            "edges": [(hex(f), hex(t)) for f, t in self.edges],
        }


@dataclass
class CallGraph:
    functions: list["Function"]
    edges: list[tuple]  # (caller_addr, callee_addr)
    _manager: Optional["FunctionManager"] = None
    _native: Optional[Any] = None

    @property
    def native(self) -> Optional[Any]:
        return self._native

    def callers(self, func_addr: int) -> list["Function"]:
        caller_addrs = [f for f, t in self.edges if t == func_addr]
        return [f for f in self.functions if f.start in caller_addrs]

    def callees(self, func_addr: int) -> list["Function"]:
        callee_addrs = [t for f, t in self.edges if f == func_addr]
        return [f for f in self.functions if f.start in callee_addrs]

    def to_dict(self) -> dict[str, Any]:
        return {
            "functions": [f.to_dict() for f in self.functions],
            "edges": [(hex(f), hex(t)) for f, t in self.edges],
        }


@dataclass
class Symbol:
    address: int
    name: str
    symbol_type: str
    size: Optional[int] = None
    _manager: Optional["SymbolManager"] = None
    _native: Optional[Any] = None

    @property
    def native(self) -> Optional[Any]:
        return self._native

    def xrefs_to(self) -> list["XRef"]:
        if self._manager and hasattr(self._manager, "_analyzer"):
            return self._manager._analyzer.xrefs.xrefs_to(self.address)
        return []

    def xrefs_from(self) -> list["XRef"]:
        if self._manager and hasattr(self._manager, "_analyzer"):
            return self._manager._analyzer.xrefs.xrefs_from(self.address)
        return []

    def to_dict(self) -> dict[str, Any]:
        return {
            "address": hex(self.address),
            "name": self.name,
            "symbol_type": self.symbol_type,
            "size": self.size,
        }
