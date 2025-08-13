"""Ghidra manager implementations."""

import json
import os
import subprocess
import tempfile
from typing import List, Optional, Dict, Any
from ..base import FunctionManager, XRefManager, SymbolManager, BinaryManager
from ..base import Function, BasicBlock, XRef, Symbol, Instruction, Variable, Type


class GhidraFunctionManager(FunctionManager):
    """Ghidra function implementation."""
    
    def __init__(self, ghidra_native, analyzer=None):
        self.ghidra = ghidra_native
        self._analyzer = analyzer
        self._functions_cache = None
    
    def get_available_levels(self) -> List[str]:
        """Get available representation levels."""
        return ["disassembly", "pcode", "pseudocode"]
    
    def get_all(self, level: Optional[str] = None) -> List[Function]:
        """Get all functions, optionally at specific representation level."""
        if self._functions_cache is None:
            self._load_functions()
        
        functions = []
        for func_data in self._functions_cache.get('functions', []):
            functions.append(Function(
                start=int(func_data['start'], 16),
                end=int(func_data['end'], 16),
                name=func_data.get('name'),
                size=func_data.get('size'),
                level=level or "disassembly",
                _manager=self,
                _native=func_data
            ))
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
        for func in self.get_all(level):
            if func.start <= addr < func.end:
                return func
        return None
    
    def get_decompiled_code(self, addr: int, level: Optional[str] = None) -> Optional[str]:
        """Get decompiled code for function at address."""
        func = self.get_function_containing(addr)
        if not func:
            return None
        
        # Use Ghidra headless to decompile specific function
        try:
            script_content = f"""
//@category LUDI
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.listing.Function;

public void run() throws Exception {{
    DecompInterface decompiler = new DecompInterface();
    decompiler.openProgram(currentProgram);
    
    Function func = getFunctionAt(toAddr(0x{addr:x}));
    if (func != null) {{
        DecompileResults results = decompiler.decompileFunction(func, 60, null);
        if (results.decompileCompleted()) {{
            println(results.getDecompiledFunction().getC());
        }}
    }}
    
    decompiler.closeProgram();
}}
"""
            return self.ghidra._run_script(script_content, "decompile")
        except Exception:
            return None
    
    def get_basic_blocks(self, addr: int, level: Optional[str] = None) -> List[BasicBlock]:
        """Get basic blocks for function."""
        # This would require more complex Ghidra scripting
        # For now, return empty list
        return []
    
    def get_instructions(self, addr: int, level: Optional[str] = None) -> List[Instruction]:
        """Get instructions for function at specific level."""
        func = self.get_function_containing(addr)
        if not func:
            return []
        
        # Use Ghidra scripting to get instructions
        try:
            script_content = f"""
//@category LUDI
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;

public void run() throws Exception {{
    Function func = getFunctionAt(toAddr(0x{addr:x}));
    if (func != null) {{
        for (Instruction instr : currentProgram.getListing().getInstructions(func.getBody(), true)) {{
            println(instr.getAddress() + ":" + instr.getMnemonicString() + ":" + instr.getDefaultOperandRepresentation(0));
        }}
    }}
}}
"""
            result = self.ghidra._run_script(script_content, "instructions")
            instructions = []
            
            if result:
                for line in result.strip().split('\n'):
                    if ':' in line:
                        parts = line.split(':', 2)
                        if len(parts) >= 2:
                            addr_str = parts[0]
                            mnemonic = parts[1]
                            operand = parts[2] if len(parts) > 2 else ""
                            
                            try:
                                instr_addr = int(addr_str, 16)
                                instructions.append(Instruction(
                                    address=instr_addr,
                                    mnemonic=mnemonic,
                                    operands=[operand] if operand else [],
                                    level=level or "disassembly",
                                    _native=None
                                ))
                            except ValueError:
                                continue
            
            return instructions
        except Exception:
            return []
    
    def _load_functions(self):
        """Load functions using Ghidra headless analysis."""
        script_content = """
//@category LUDI
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;

public void run() throws Exception {
    FunctionManager fm = currentProgram.getFunctionManager();
    
    for (Function func : fm.getFunctions(true)) {
        println("{");
        println("  \\"name\\": \\"" + func.getName() + "\\",");
        println("  \\"start\\": \\"" + func.getEntryPoint() + "\\",");
        println("  \\"end\\": \\"" + func.getBody().getMaxAddress() + "\\",");
        println("  \\"size\\": " + func.getBody().getNumAddresses());
        println("},");
    }
}
"""
        
        try:
            result = self.ghidra._run_script(script_content, "functions")
            if result:
                # Parse the output as JSON-like format
                functions_data = []
                lines = result.strip().split('\n')
                current_func = {}
                
                for line in lines:
                    line = line.strip()
                    if line == '{':
                        current_func = {}
                    elif line == '},':
                        if current_func:
                            functions_data.append(current_func)
                            current_func = {}
                    elif ':' in line:
                        parts = line.split(':', 1)
                        if len(parts) == 2:
                            key = parts[0].strip().strip('"')
                            value = parts[1].strip().rstrip(',').strip('"')
                            if key in ['size']:
                                try:
                                    value = int(value)
                                except ValueError:
                                    pass
                            current_func[key] = value
                
                self._functions_cache = {'functions': functions_data}
            else:
                self._functions_cache = {'functions': []}
        except Exception:
            self._functions_cache = {'functions': []}


class GhidraXRefManager(XRefManager):
    """Ghidra xref implementation."""
    
    def __init__(self, ghidra_native, analyzer=None):
        self.ghidra = ghidra_native
        self._analyzer = analyzer
    
    def get_xrefs_to(self, addr: int) -> List[XRef]:
        """Get xrefs to address."""
        script_content = f"""
//@category LUDI
import ghidra.program.model.symbol.Reference;

public void run() throws Exception {{
    for (Reference ref : getReferencesTo(toAddr(0x{addr:x}))) {{
        println(ref.getFromAddress() + ":" + ref.getToAddress() + ":" + ref.getReferenceType());
    }}
}}
"""
        
        try:
            result = self.ghidra._run_script(script_content, "xrefs_to")
            xrefs = []
            
            if result:
                for line in result.strip().split('\n'):
                    if ':' in line:
                        parts = line.split(':', 2)
                        if len(parts) >= 3:
                            try:
                                from_addr = int(parts[0], 16)
                                to_addr = int(parts[1], 16)
                                ref_type = parts[2].lower()
                                
                                xrefs.append(XRef(
                                    from_addr=from_addr,
                                    to_addr=to_addr,
                                    xref_type=ref_type,
                                    _manager=self,
                                    _native=None
                                ))
                            except ValueError:
                                continue
            
            return xrefs
        except Exception:
            return []
    
    def get_xrefs_from(self, addr: int) -> List[XRef]:
        """Get xrefs from address."""
        script_content = f"""
//@category LUDI
import ghidra.program.model.symbol.Reference;

public void run() throws Exception {{
    for (Reference ref : getReferencesFrom(toAddr(0x{addr:x}))) {{
        println(ref.getFromAddress() + ":" + ref.getToAddress() + ":" + ref.getReferenceType());
    }}
}}
"""
        
        try:
            result = self.ghidra._run_script(script_content, "xrefs_from")
            xrefs = []
            
            if result:
                for line in result.strip().split('\n'):
                    if ':' in line:
                        parts = line.split(':', 2)
                        if len(parts) >= 3:
                            try:
                                from_addr = int(parts[0], 16)
                                to_addr = int(parts[1], 16)
                                ref_type = parts[2].lower()
                                
                                xrefs.append(XRef(
                                    from_addr=from_addr,
                                    to_addr=to_addr,
                                    xref_type=ref_type,
                                    _manager=self,
                                    _native=None
                                ))
                            except ValueError:
                                continue
            
            return xrefs
        except Exception:
            return []
    
    def get_all_xrefs(self) -> List[XRef]:
        """Get all xrefs."""
        # This would be very expensive for large binaries
        # Return empty list for now
        return []
    
    def get_call_graph(self) -> dict:
        """Get call graph data."""
        # This would require complex Ghidra scripting
        return {}
    
    def get_data_flow(self, addr: int) -> dict:
        """Get data flow information."""
        return {"reads": [], "writes": [], "uses": []}


class GhidraSymbolManager(SymbolManager):
    """Ghidra symbol implementation."""
    
    def __init__(self, ghidra_native, analyzer=None):
        self.ghidra = ghidra_native
        self._analyzer = analyzer
    
    def get_all(self) -> List[Symbol]:
        """Get all symbols."""
        script_content = """
//@category LUDI
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolTable;

public void run() throws Exception {
    SymbolTable st = currentProgram.getSymbolTable();
    
    for (Symbol symbol : st.getAllSymbols(true)) {
        if (!symbol.isDynamic() && !symbol.isExternal()) {
            println(symbol.getAddress() + ":" + symbol.getName() + ":" + symbol.getSymbolType());
        }
    }
}
"""
        
        try:
            result = self.ghidra._run_script(script_content, "symbols")
            symbols = []
            
            if result:
                for line in result.strip().split('\n'):
                    if ':' in line:
                        parts = line.split(':', 2)
                        if len(parts) >= 3:
                            try:
                                addr = int(parts[0], 16)
                                name = parts[1]
                                symbol_type = parts[2].lower()
                                
                                symbols.append(Symbol(
                                    address=addr,
                                    name=name,
                                    symbol_type=symbol_type,
                                    _manager=self,
                                    _native=None
                                ))
                            except ValueError:
                                continue
            
            return symbols
        except Exception:
            return []
    
    def get_by_address(self, addr: int) -> Optional[Symbol]:
        """Get symbol at address."""
        for symbol in self.get_all():
            if symbol.address == addr:
                return symbol
        return None
    
    def get_by_name(self, name: str) -> Optional[Symbol]:
        """Get symbol by name."""
        for symbol in self.get_all():
            if symbol.name == name:
                return symbol
        return None
    
    def get_variables(self, scope: Optional[int] = None) -> List[Variable]:
        """Get variables (optionally scoped to function)."""
        # Ghidra variable analysis would require complex scripting
        # Return empty list for now
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
        script_content = """
//@category LUDI
import ghidra.program.model.data.StringDataInstance;

public void run() throws Exception {
    for (StringDataInstance str : currentProgram.getListing().getDefinedStrings()) {
        if (str.getStringValue().length() > 0) {
            println(str.getAddress() + ":" + str.getStringValue());
        }
    }
}
"""
        
        try:
            result = self.ghidra._run_script(script_content, "strings")
            strings = []
            
            if result:
                for line in result.strip().split('\n'):
                    if ':' in line:
                        parts = line.split(':', 1)
                        if len(parts) >= 2:
                            try:
                                addr = int(parts[0], 16)
                                string_value = parts[1]
                                
                                strings.append(Symbol(
                                    address=addr,
                                    name=string_value,
                                    symbol_type="string",
                                    _manager=self,
                                    _native=None
                                ))
                            except ValueError:
                                continue
            
            return strings
        except Exception:
            return []


class GhidraBinaryManager(BinaryManager):
    """Ghidra binary file format implementation."""
    
    def __init__(self, ghidra_native, analyzer=None):
        self.ghidra = ghidra_native
        self._analyzer = analyzer
    
    def get_segments(self) -> List[dict]:
        """Get memory segments."""
        script_content = """
//@category LUDI
import ghidra.program.model.mem.MemoryBlock;

public void run() throws Exception {
    for (MemoryBlock block : currentProgram.getMemory().getBlocks()) {
        println("{");
        println("  \\"name\\": \\"" + block.getName() + "\\",");
        println("  \\"start\\": \\"" + block.getStart() + "\\",");
        println("  \\"end\\": \\"" + block.getEnd() + "\\",");
        println("  \\"size\\": " + block.getSize() + ",");
        println("  \\"permissions\\": \\"" + (block.isRead() ? "r" : "") + (block.isWrite() ? "w" : "") + (block.isExecute() ? "x" : "") + "\\"");
        println("},");
    }
}
"""
        
        try:
            result = self.ghidra._run_script(script_content, "segments")
            segments = []
            
            if result:
                lines = result.strip().split('\n')
                current_segment = {}
                
                for line in lines:
                    line = line.strip()
                    if line == '{':
                        current_segment = {}
                    elif line == '},':
                        if current_segment:
                            # Convert addresses
                            if 'start' in current_segment:
                                current_segment['start'] = int(current_segment['start'], 16)
                            if 'end' in current_segment:
                                current_segment['end'] = int(current_segment['end'], 16)
                            segments.append(current_segment)
                            current_segment = {}
                    elif ':' in line:
                        parts = line.split(':', 1)
                        if len(parts) == 2:
                            key = parts[0].strip().strip('"')
                            value = parts[1].strip().rstrip(',').strip('"')
                            if key in ['size']:
                                try:
                                    value = int(value)
                                except ValueError:
                                    pass
                            current_segment[key] = value
            
            return segments
        except Exception:
            return []
    
    def get_sections(self) -> List[dict]:
        """Get file sections."""
        # For Ghidra, sections are similar to segments
        return self.get_segments()
    
    def get_imports(self) -> List[Symbol]:
        """Get imported functions/symbols."""
        script_content = """
//@category LUDI
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolTable;

public void run() throws Exception {
    SymbolTable st = currentProgram.getSymbolTable();
    
    for (Symbol symbol : st.getExternalSymbols()) {
        println(symbol.getAddress() + ":" + symbol.getName() + ":import");
    }
}
"""
        
        try:
            result = self.ghidra._run_script(script_content, "imports")
            imports = []
            
            if result:
                for line in result.strip().split('\n'):
                    if ':' in line:
                        parts = line.split(':', 2)
                        if len(parts) >= 2:
                            try:
                                addr = int(parts[0], 16)
                                name = parts[1]
                                
                                imports.append(Symbol(
                                    address=addr,
                                    name=name,
                                    symbol_type="import",
                                    _manager=None,
                                    _native=None
                                ))
                            except ValueError:
                                continue
            
            return imports
        except Exception:
            return []
    
    def get_exports(self) -> List[Symbol]:
        """Get exported functions/symbols."""
        # Ghidra doesn't have explicit exports like PE/ELF
        # Return functions that are publicly visible
        return []
    
    def get_entry_points(self) -> List[int]:
        """Get program entry points."""
        script_content = """
//@category LUDI
import ghidra.program.model.symbol.Symbol;

public void run() throws Exception {
    for (Symbol symbol : currentProgram.getSymbolTable().getSymbols("entry")) {
        println(symbol.getAddress());
    }
}
"""
        
        try:
            result = self.ghidra._run_script(script_content, "entry_points")
            entry_points = []
            
            if result:
                for line in result.strip().split('\n'):
                    if line:
                        try:
                            addr = int(line, 16)
                            entry_points.append(addr)
                        except ValueError:
                            continue
            
            return entry_points
        except Exception:
            return []
    
    def get_file_info(self) -> dict:
        """Get file format information."""
        script_content = """
//@category LUDI

public void run() throws Exception {
    println("filename:" + currentProgram.getName());
    println("format:" + currentProgram.getExecutableFormat());
    println("arch:" + currentProgram.getLanguage().getProcessor().toString());
    println("bits:" + currentProgram.getAddressFactory().getDefaultAddressSpace().getSize());
    println("endian:" + (currentProgram.getLanguage().isBigEndian() ? "big" : "little"));
    println("base:" + currentProgram.getImageBase());
}
"""
        
        try:
            result = self.ghidra._run_script(script_content, "file_info")
            file_info = {
                "filename": "unknown",
                "filetype": "unknown",
                "architecture": "unknown",
                "bits": 32,
                "endian": "little",
                "base_address": 0
            }
            
            if result:
                for line in result.strip().split('\n'):
                    if ':' in line:
                        key, value = line.split(':', 1)
                        if key == "filename":
                            file_info["filename"] = value
                        elif key == "format":
                            file_info["filetype"] = value
                        elif key == "arch":
                            file_info["architecture"] = value
                        elif key == "bits":
                            try:
                                file_info["bits"] = int(value)
                            except ValueError:
                                pass
                        elif key == "endian":
                            file_info["endian"] = value
                        elif key == "base":
                            try:
                                file_info["base_address"] = int(value, 16)
                            except ValueError:
                                pass
            
            return file_info
        except Exception:
            return {
                "filename": "unknown",
                "filetype": "unknown",
                "architecture": "unknown",
                "bits": 32,
                "endian": "little",
                "base_address": 0
            }