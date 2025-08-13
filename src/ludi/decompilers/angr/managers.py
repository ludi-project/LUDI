"""angr manager implementations."""

from typing import List, Optional, Dict, Any
from ..base import FunctionManager, XRefManager, SymbolManager, BinaryManager
from ..base import Function, BasicBlock, XRef, Symbol, Instruction, Variable, Type


class AngrFunctionManager(FunctionManager):
    """angr function implementation."""
    
    def __init__(self, angr_native, analyzer=None):
        self.angr = angr_native
        self._analyzer = analyzer
    
    def get_available_levels(self) -> List[str]:
        """Get available representation levels."""
        levels = ["disassembly", "vex"]
        # Check if decompiler is available
        try:
            if hasattr(self.angr, 'analyses') and hasattr(self.angr.analyses, 'Decompiler'):
                levels.append("pseudocode")
        except:
            pass
        return levels
    
    def get_all(self, level: Optional[str] = None) -> List[Function]:
        """Get all functions, optionally at specific representation level."""
        functions = []
        
        try:
            # Use angr's CFG to get functions
            if not hasattr(self.angr, '_cfg'):
                # Generate CFG if not exists
                self.angr._cfg = self.angr.analyses.CFGFast()
            
            cfg = self.angr._cfg
            
            for func_addr, func in cfg.functions.items():
                name = func.name if func.name else None
                # Calculate size from basic blocks
                size = 0
                if func.blocks:
                    addresses = [block.addr for block in func.blocks]
                    if addresses:
                        size = max(addresses) - min(addresses) + 4  # Rough estimate
                
                functions.append(Function(
                    start=func.addr,
                    end=func.addr + size,
                    name=name,
                    size=size,
                    level=level or "disassembly",
                    _manager=self,
                    _native=func
                ))
        except Exception:
            # CFG generation can fail, return empty list
            pass
        
        return functions
    
    def get_by_address(self, addr: int, level: Optional[str] = None) -> Optional[Function]:
        """Get function at address, optionally at specific level."""
        for func in self.get_all(level):
            if func.start == addr:
                return func
        return None
    
    def get_by_name(self, name: str) -> Optional[Function]:
        """Get function by name."""
        for func in self.get_all():
            if func.name == name:
                return func
        return None
    
    def get_function_containing(self, addr: int, level: Optional[str] = None) -> Optional[Function]:
        """Get function that contains the given address."""
        try:
            if not hasattr(self.angr, '_cfg'):
                self.angr._cfg = self.angr.analyses.CFGFast()
            
            cfg = self.angr._cfg
            func = cfg.functions.floor_func(addr)
            
            if func and func.addr <= addr:
                # Check if address is within function bounds
                if func.blocks:
                    max_addr = max(block.addr + block.size for block in func.blocks)
                    if addr < max_addr:
                        name = func.name if func.name else None
                        size = max_addr - func.addr
                        
                        return Function(
                            start=func.addr,
                            end=func.addr + size,
                            name=name,
                            size=size,
                            level=level or "disassembly",
                            _manager=self,
                            _native=func
                        )
        except Exception:
            pass
        
        return None
    
    def get_decompiled_code(self, addr: int, level: Optional[str] = None) -> Optional[str]:
        """Get decompiled code for function at address."""
        try:
            if not hasattr(self.angr, '_cfg'):
                self.angr._cfg = self.angr.analyses.CFGFast()
            
            cfg = self.angr._cfg
            func = cfg.functions.get(addr)
            if not func:
                func = cfg.functions.floor_func(addr)
            
            if func:
                if level == "pseudocode" or level is None:
                    # Try to use angr's decompiler
                    try:
                        if hasattr(self.angr.analyses, 'Decompiler'):
                            # Normalize the function before decompilation
                            # This is required by angr's decompiler
                            try:
                                func.normalize()
                            except Exception:
                                # Normalization may fail for some functions, continue anyway
                                pass
                            
                            dec = self.angr.analyses.Decompiler(func, fail_fast=True)
                            if dec.codegen and dec.codegen.text:
                                return dec.codegen.text
                    except Exception:
                        pass
                
                # Fallback to disassembly
                if level == "disassembly" or level is None:
                    try:
                        disasm_lines = []
                        for block in func.blocks:
                            block_obj = self.angr.factory.block(block.addr, size=block.size)
                            for insn in block_obj.disassembly.insns:
                                disasm_lines.append(f"0x{insn.address:x}: {insn.mnemonic} {insn.op_str}")
                        return "\n".join(disasm_lines)
                    except Exception:
                        pass
                
                # VEX IR fallback
                if level == "vex":
                    try:
                        vex_lines = []
                        for block in func.blocks:
                            block_obj = self.angr.factory.block(block.addr, size=block.size)
                            vex_lines.append(f"Block 0x{block.addr:x}:")
                            vex_lines.append(str(block_obj.vex))
                        return "\n".join(vex_lines)
                    except Exception:
                        pass
        except Exception:
            pass
        
        return None
    
    def get_basic_blocks(self, addr: int, level: Optional[str] = None) -> List[BasicBlock]:
        """Get basic blocks for function."""
        try:
            if not hasattr(self.angr, '_cfg'):
                self.angr._cfg = self.angr.analyses.CFGFast()
            
            cfg = self.angr._cfg
            func = cfg.functions.get(addr)
            if not func:
                func = cfg.functions.floor_func(addr)
            
            if func:
                blocks = []
                for block in func.blocks:
                    # Get instructions for this block
                    instructions = []
                    try:
                        block_obj = self.angr.factory.block(block.addr, size=block.size)
                        for insn in block_obj.disassembly.insns:
                            instructions.append(Instruction(
                                address=insn.address,
                                mnemonic=insn.mnemonic,
                                operands=[insn.op_str] if insn.op_str else [],
                                level=level or "disassembly",
                                _native=insn
                            ))
                    except Exception:
                        # If disassembly fails, create placeholder
                        instructions.append(Instruction(
                            address=block.addr,
                            mnemonic="unknown",
                            operands=[],
                            level=level or "disassembly",
                            _native=None
                        ))
                    
                    blocks.append(BasicBlock(
                        start=block.addr,
                        end=block.addr + block.size,
                        instructions=instructions,
                        size=block.size,
                        level=level or "disassembly",
                        _native=block
                    ))
                
                return blocks
        except Exception:
            pass
        
        return []
    
    def get_instructions(self, addr: int, level: Optional[str] = None) -> List[Instruction]:
        """Get instructions for function at specific level."""
        instructions = []
        for block in self.get_basic_blocks(addr, level):
            instructions.extend(block.instructions)
        return instructions


class AngrXRefManager(XRefManager):
    """angr xref implementation."""
    
    def __init__(self, angr_native, analyzer=None):
        self.angr = angr_native
        self._analyzer = analyzer
    
    def get_xrefs_to(self, addr: int) -> List[XRef]:
        """Get xrefs to address."""
        xrefs = []
        
        try:
            if not hasattr(self.angr, '_cfg'):
                self.angr._cfg = self.angr.analyses.CFGFast()
            
            cfg = self.angr._cfg
            
            # Look for references to this address
            for func_addr, func in cfg.functions.items():
                for block in func.blocks:
                    try:
                        block_obj = self.angr.factory.block(block.addr, size=block.size)
                        for insn in block_obj.disassembly.insns:
                            # Simple heuristic: look for address in operands
                            if insn.op_str and hex(addr) in insn.op_str:
                                xref_type = "call" if "call" in insn.mnemonic.lower() else "data"
                                xrefs.append(XRef(
                                    from_addr=insn.address,
                                    to_addr=addr,
                                    xref_type=xref_type,
                                    _manager=self,
                                    _native=None
                                ))
                    except Exception:
                        continue
        except Exception:
            pass
        
        return xrefs
    
    def get_xrefs_from(self, addr: int) -> List[XRef]:
        """Get xrefs from address."""
        xrefs = []
        
        try:
            if not hasattr(self.angr, '_cfg'):
                self.angr._cfg = self.angr.analyses.CFGFast()
            
            cfg = self.angr._cfg
            
            # Find the instruction at this address
            func = cfg.functions.floor_func(addr)
            if func:
                for block in func.blocks:
                    if block.addr <= addr < block.addr + block.size:
                        try:
                            block_obj = self.angr.factory.block(block.addr, size=block.size)
                            for insn in block_obj.disassembly.insns:
                                if insn.address == addr:
                                    # Parse operands for addresses
                                    if insn.op_str:
                                        # Simple heuristic for finding addresses
                                        import re
                                        addr_matches = re.findall(r'0x[0-9a-fA-F]+', insn.op_str)
                                        for addr_str in addr_matches:
                                            try:
                                                target_addr = int(addr_str, 16)
                                                xref_type = "call" if "call" in insn.mnemonic.lower() else "data"
                                                xrefs.append(XRef(
                                                    from_addr=addr,
                                                    to_addr=target_addr,
                                                    xref_type=xref_type,
                                                    _manager=self,
                                                    _native=None
                                                ))
                                            except ValueError:
                                                continue
                                    break
                        except Exception:
                            continue
                        break
        except Exception:
            pass
        
        return xrefs
    
    def get_all_xrefs(self) -> List[XRef]:
        """Get all xrefs."""
        # This would be very expensive, return empty list
        return []
    
    def get_call_graph(self) -> dict:
        """Get call graph data."""
        call_graph = {}
        
        try:
            if not hasattr(self.angr, '_cfg'):
                self.angr._cfg = self.angr.analyses.CFGFast()
            
            cfg = self.angr._cfg
            
            for func_addr, func in cfg.functions.items():
                calls = []
                # Get function calls from this function
                for callsite in func.get_call_sites():
                    target = func.get_call_target(callsite)
                    if target:
                        calls.append(target)
                call_graph[func_addr] = calls
        except Exception:
            pass
        
        return call_graph
    
    def get_data_flow(self, addr: int) -> dict:
        """Get data flow information."""
        # angr data flow analysis would be complex
        return {"reads": [], "writes": [], "uses": []}


class AngrSymbolManager(SymbolManager):
    """angr symbol implementation."""
    
    def __init__(self, angr_native, analyzer=None):
        self.angr = angr_native
        self._analyzer = analyzer
    
    def get_all(self) -> List[Symbol]:
        """Get all symbols."""
        symbols = []
        
        try:
            # Get symbols from angr's loader
            for name, symbol in self.angr.loader.main_object.symbols_by_name.items():
                if symbol.is_function:
                    symbol_type = "function"
                else:
                    symbol_type = "data"
                
                symbols.append(Symbol(
                    address=symbol.rebased_addr,
                    name=name,
                    symbol_type=symbol_type,
                    size=symbol.size if hasattr(symbol, 'size') else None,
                    _manager=self,
                    _native=symbol
                ))
        except Exception:
            pass
        
        return symbols
    
    def get_by_address(self, addr: int) -> Optional[Symbol]:
        """Get symbol at address."""
        try:
            symbol = self.angr.loader.find_symbol(addr)
            if symbol:
                symbol_type = "function" if symbol.is_function else "data"
                return Symbol(
                    address=symbol.rebased_addr,
                    name=symbol.name,
                    symbol_type=symbol_type,
                    size=symbol.size if hasattr(symbol, 'size') else None,
                    _manager=self,
                    _native=symbol
                )
        except Exception:
            pass
        
        return None
    
    def get_by_name(self, name: str) -> Optional[Symbol]:
        """Get symbol by name."""
        try:
            symbol = self.angr.loader.find_symbol(name)
            if symbol:
                symbol_type = "function" if symbol.is_function else "data"
                return Symbol(
                    address=symbol.rebased_addr,
                    name=symbol.name,
                    symbol_type=symbol_type,
                    size=symbol.size if hasattr(symbol, 'size') else None,
                    _manager=self,
                    _native=symbol
                )
        except Exception:
            pass
        
        return None
    
    def get_variables(self, scope: Optional[int] = None) -> List[Variable]:
        """Get variables (optionally scoped to function)."""
        # angr variable analysis would require complex analysis
        return []
    
    def get_types(self) -> List[Type]:
        """Get type information."""
        # Basic primitive types
        return [
            Type(name="char", size=1, kind="primitive"),
            Type(name="short", size=2, kind="primitive"),
            Type(name="int", size=4, kind="primitive"),
            Type(name="long", size=8, kind="primitive"),
            Type(name="float", size=4, kind="primitive"),
            Type(name="double", size=8, kind="primitive"),
            Type(name="void*", size=8, kind="primitive"),
        ]
    
    def get_strings(self) -> List[Symbol]:
        """Get string literals."""
        strings = []
        
        try:
            # Look for strings in the binary
            for section in self.angr.loader.main_object.sections:
                if section.is_readable and not section.is_executable:
                    try:
                        data = self.angr.loader.memory.load(section.vaddr, section.memsize)
                        # Simple string detection
                        current_string = b""
                        string_start = section.vaddr
                        
                        for i, byte in enumerate(data):
                            if 32 <= byte <= 126:  # Printable ASCII
                                current_string += bytes([byte])
                            else:
                                if len(current_string) >= 4:  # Minimum string length
                                    strings.append(Symbol(
                                        address=string_start,
                                        name=current_string.decode('ascii', errors='ignore'),
                                        symbol_type="string",
                                        size=len(current_string),
                                        _manager=self,
                                        _native=None
                                    ))
                                current_string = b""
                                string_start = section.vaddr + i + 1
                        
                        # Handle string at end of section
                        if len(current_string) >= 4:
                            strings.append(Symbol(
                                address=string_start,
                                name=current_string.decode('ascii', errors='ignore'),
                                symbol_type="string",
                                size=len(current_string),
                                _manager=self,
                                _native=None
                            ))
                    except Exception:
                        continue
        except Exception:
            pass
        
        return strings


class AngrBinaryManager(BinaryManager):
    """angr binary file format implementation."""
    
    def __init__(self, angr_native, analyzer=None):
        self.angr = angr_native
        self._analyzer = analyzer
    
    def get_segments(self) -> List[dict]:
        """Get memory segments."""
        segments = []
        
        try:
            for section in self.angr.loader.main_object.sections:
                permissions = ""
                if section.is_readable:
                    permissions += "r"
                if section.is_writable:
                    permissions += "w"
                if section.is_executable:
                    permissions += "x"
                
                segments.append({
                    "name": section.name,
                    "start": section.vaddr,
                    "end": section.vaddr + section.memsize,
                    "size": section.memsize,
                    "permissions": permissions
                })
        except Exception:
            pass
        
        return segments
    
    def get_sections(self) -> List[dict]:
        """Get file sections."""
        return self.get_segments()  # Same as segments for angr
    
    def get_imports(self) -> List[Symbol]:
        """Get imported functions/symbols."""
        imports = []
        
        try:
            # Get PLT symbols (imports)
            for name, symbol in self.angr.loader.main_object.symbols_by_name.items():
                if symbol.is_import:
                    imports.append(Symbol(
                        address=symbol.rebased_addr,
                        name=name,
                        symbol_type="import",
                        _manager=None,
                        _native=symbol
                    ))
        except Exception:
            pass
        
        return imports
    
    def get_exports(self) -> List[Symbol]:
        """Get exported functions/symbols."""
        exports = []
        
        try:
            # Get exported symbols
            for name, symbol in self.angr.loader.main_object.symbols_by_name.items():
                if symbol.is_export:
                    exports.append(Symbol(
                        address=symbol.rebased_addr,
                        name=name,
                        symbol_type="export",
                        _manager=None,
                        _native=symbol
                    ))
        except Exception:
            pass
        
        return exports
    
    def get_entry_points(self) -> List[int]:
        """Get program entry points."""
        try:
            return [self.angr.entry]
        except Exception:
            return []
    
    def get_file_info(self) -> dict:
        """Get file format information."""
        try:
            main_obj = self.angr.loader.main_object
            
            # Map angr arch to readable names
            arch_map = {
                'X86': 'x86',
                'AMD64': 'x86_64',
                'ARM': 'arm',
                'AARCH64': 'aarch64',
                'MIPS32': 'mips',
                'MIPS64': 'mips64'
            }
            
            arch_name = arch_map.get(main_obj.arch.name, main_obj.arch.name.lower())
            
            return {
                "filename": main_obj.binary,
                "filetype": main_obj.os,
                "architecture": arch_name,
                "bits": main_obj.arch.bits,
                "endian": "big" if main_obj.arch.memory_endness == "Iend_BE" else "little",
                "base_address": main_obj.min_addr
            }
        except Exception:
            return {
                "filename": "unknown",
                "filetype": "unknown",
                "architecture": "unknown",
                "bits": 32,
                "endian": "little",
                "base_address": 0
            }