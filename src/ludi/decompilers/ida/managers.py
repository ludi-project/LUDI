from typing import List, Optional
from ..base import FunctionManager, XRefManager, SymbolManager, BinaryManager
from ..base import Function, BasicBlock, XRef, Symbol, Instruction, Variable, Type


class IdaFunctionManager(FunctionManager):
    """IDA function implementation."""
    
    def __init__(self, ida_native, analyzer=None):
        self.ida = ida_native
        self._analyzer = analyzer
    
    def get_available_levels(self) -> List[str]:
        """Get available representation levels."""
        levels = ["disassembly"]
        # Check if decompiler is available
        try:
            if hasattr(self.ida, 'ida_hexrays') and self.ida.ida_hexrays.init_hexrays_plugin():
                levels.extend(["microcode", "pseudocode"])
        except:
            pass
        return levels
    
    def get_all(self, level: Optional[str] = None) -> List[Function]:
        """Get all functions, optionally at specific representation level."""
        functions = []
        for func_ea in self.ida.idautils.Functions():
            func = self.ida.ida_funcs.get_func(func_ea)
            if func:
                name = self.ida.ida_name.get_name(func.start_ea)
                functions.append(Function(
                    start=func.start_ea,
                    end=func.end_ea,
                    name=name if name else None,
                    size=func.size(),
                    level=level or "disassembly",
                    _manager=self,
                    _native=func
                ))
        return functions
    
    def get_by_address(self, addr: int, level: Optional[str] = None) -> Optional[Function]:
        """Get function at address, optionally at specific level."""
        func = self.ida.ida_funcs.get_func(addr)
        if func:
            name = self.ida.ida_name.get_name(func.start_ea)
            return Function(
                start=func.start_ea,
                end=func.end_ea,
                name=name if name else None,
                size=func.size(),
                level=level or "disassembly",
                _manager=self,
                _native=func
            )
        return None
    
    def get_by_name(self, name: str) -> Optional[Function]:
        """Get function by name."""
        addr = self.ida.ida_name.get_name_ea(self.ida.idc.BADADDR, name)
        if addr != self.ida.idc.BADADDR:
            return self.get_by_address(addr)
        return None
    
    def get_function_containing(self, addr: int, level: Optional[str] = None) -> Optional[Function]:
        """Get function that contains the given address."""
        func = self.ida.ida_funcs.get_func(addr)
        if func:
            name = self.ida.ida_name.get_name(func.start_ea)
            return Function(
                start=func.start_ea,
                end=func.end_ea,
                name=name if name else None,
                size=func.size(),
                level=level or "disassembly",
                _manager=self,
                _native=func
            )
        return None
    
    def get_decompiled_code(self, addr: int, level: Optional[str] = None) -> Optional[str]:
        """Get decompiled code for function at address."""
        # First ensure we have the function
        func = self.ida.ida_funcs.get_func(addr)
        if not func:
            return None
        
        if level == "pseudocode" or level is None:
            # Try to get pseudocode using Hex-Rays
            try:
                if hasattr(self.ida, 'ida_hexrays') and self.ida.ida_hexrays.init_hexrays_plugin():
                    cfunc = self.ida.ida_hexrays.decompile(func.start_ea)
                    if cfunc:
                        return str(cfunc)
            except Exception:
                pass
        
        # Fallback to disassembly
        if level == "disassembly" or level is None:
            try:
                lines = []
                for ea in func.code_items():
                    disasm = self.ida.idc.GetDisasm(ea)
                    if disasm:
                        lines.append(f"0x{ea:x}: {disasm}")
                return "\n".join(lines)
            except Exception:
                pass
        
        return None
    
    def get_basic_blocks(self, addr: int, level: Optional[str] = None) -> List[BasicBlock]:
        """Get basic blocks for function."""
        func = self.ida.ida_funcs.get_func(addr)
        if not func:
            return []
        
        blocks = []
        instr_addrs = list(func.code_items())
        flowchart = self.ida.ida_gdl.FlowChart(f=func, flags=self.ida.ida_gdl.FC_PREDS)
        
        for block in flowchart:
            # Get instruction addresses for this block
            block_instr_addrs = [
                ea for ea in instr_addrs 
                if block.start_ea <= ea < block.end_ea
            ]
            
            # Create Instruction objects for this block
            instructions = []
            for ea in block_instr_addrs:
                mnemonic = self.ida.ida_ua.print_insn_mnem(ea)
                operands = []
                for i in range(6):  # IDA max operands
                    op_str = self.ida.ida_ua.print_operand(ea, i)
                    if op_str:
                        operands.append(op_str)
                    else:
                        break
                
                instructions.append(Instruction(
                    address=ea,
                    mnemonic=mnemonic,
                    operands=operands,
                    level=level or "disassembly",
                    _native=None  # IDA doesn't have instruction objects
                ))
            
            blocks.append(BasicBlock(
                start=block.start_ea,
                end=block.end_ea,
                instructions=instructions,
                size=block.end_ea - block.start_ea,
                level=level or "disassembly",
                _native=block
            ))
        
        return blocks
    
    def get_instructions(self, addr: int, level: Optional[str] = None) -> List[Instruction]:
        """Get instructions for function at specific level."""
        func = self.ida.ida_funcs.get_func(addr)
        if not func:
            return []
        
        instructions = []
        for ea in func.code_items():
            mnemonic = self.ida.ida_ua.print_insn_mnem(ea)
            operands = []
            for i in range(6):  # IDA max operands
                op_str = self.ida.ida_ua.print_operand(ea, i)
                if op_str:
                    operands.append(op_str)
                else:
                    break
            
            instructions.append(Instruction(
                address=ea,
                mnemonic=mnemonic,
                operands=operands,
                level=level or "disassembly",
                _native=None  # IDA doesn't have instruction objects
            ))
        
        return instructions


class IdaXRefManager(XRefManager):
    """IDA xref implementation."""
    
    def __init__(self, ida_native, analyzer=None):
        self.ida = ida_native
        self._analyzer = analyzer
    
    def _xref_type_to_string(self, xref_type) -> str:
        """Convert IDA xref type to string."""
        if xref_type == self.ida.ida_xref.fl_CF:
            return "call"
        elif xref_type == self.ida.ida_xref.fl_JF:
            return "jump"
        elif xref_type == self.ida.ida_xref.dr_R:
            return "data_read"
        elif xref_type == self.ida.ida_xref.dr_W:
            return "data_write"
        elif xref_type == self.ida.ida_xref.dr_O:
            return "data_offset"
        else:
            return "unknown"
    
    def get_xrefs_to(self, addr: int) -> List[XRef]:
        """Get xrefs to address."""
        xrefs = []
        for xref in self.ida.idautils.XrefsTo(addr):
            xrefs.append(XRef(
                from_addr=xref.frm,
                to_addr=xref.to,
                xref_type=self._xref_type_to_string(xref.type),
                _manager=self,
                _native=xref
            ))
        return xrefs
    
    def get_xrefs_from(self, addr: int) -> List[XRef]:
        """Get xrefs from address."""
        xrefs = []
        for xref in self.ida.idautils.XrefsFrom(addr):
            xrefs.append(XRef(
                from_addr=xref.frm,
                to_addr=xref.to,
                xref_type=self._xref_type_to_string(xref.type),
                _manager=self,
                _native=xref
            ))
        return xrefs
    
    def get_all_xrefs(self) -> List[XRef]:
        """Get all xrefs."""
        all_xrefs = []
        for func_ea in self.ida.idautils.Functions():
            func = self.ida.ida_funcs.get_func(func_ea)
            if func:
                for ea in func.code_items():
                    for xref in self.ida.idautils.XrefsFrom(ea):
                        all_xrefs.append(XRef(
                            from_addr=xref.frm,
                            to_addr=xref.to,
                            xref_type=self._xref_type_to_string(xref.type),
                            _manager=self,
                            _native=xref
                        ))
        return all_xrefs
    
    def get_call_graph(self) -> dict:
        """Get call graph data."""
        call_graph = {}
        for func_ea in self.ida.idautils.Functions():
            func = self.ida.ida_funcs.get_func(func_ea)
            if func:
                calls = []
                for ea in func.code_items():
                    for xref in self.ida.idautils.XrefsFrom(ea):
                        if xref.type == self.ida.ida_xref.fl_CF:  # Call
                            target_func = self.ida.ida_funcs.get_func(xref.to)
                            if target_func:
                                calls.append(target_func.start_ea)
                call_graph[func.start_ea] = calls
        return call_graph
    
    def get_data_flow(self, addr: int) -> dict:
        """Get data flow information."""
        # Basic data flow - this would be much more complex in a real implementation
        data_flow = {
            "reads": [],
            "writes": [],
            "uses": []
        }
        func = self.ida.ida_funcs.get_func(addr)
        if func:
            for ea in func.code_items():
                for xref in self.ida.idautils.XrefsFrom(ea):
                    if xref.type == self.ida.ida_xref.dr_R:
                        data_flow["reads"].append(xref.to)
                    elif xref.type == self.ida.ida_xref.dr_W:
                        data_flow["writes"].append(xref.to)
        return data_flow


class IdaSymbolManager(SymbolManager):
    """IDA symbol implementation."""
    
    def __init__(self, ida_native, analyzer=None):
        self.ida = ida_native
        self._analyzer = analyzer
    
    def get_all(self) -> List[Symbol]:
        """Get all symbols."""
        symbols = []
        
        # Get all named locations
        for i in range(self.ida.ida_name.get_nlist_size()):
            name = self.ida.ida_name.get_nlist_name(i)
            addr = self.ida.ida_name.get_nlist_ea(i)
            if name and addr != self.ida.idc.BADADDR:
                symbol_type = self._get_symbol_type(addr)
                symbols.append(Symbol(
                    address=addr,
                    name=name,
                    symbol_type=symbol_type
                ))
        
        return symbols
    
    def get_by_address(self, addr: int) -> Optional[Symbol]:
        """Get symbol at address."""
        name = self.ida.ida_name.get_name(addr)
        if name:
            return Symbol(
                address=addr,
                name=name,
                symbol_type=self._get_symbol_type(addr),
                _manager=self,
                _native=None
            )
        return None
    
    def get_by_name(self, name: str) -> Optional[Symbol]:
        """Get symbol by name."""
        addr = self.ida.ida_name.get_name_ea(self.ida.idc.BADADDR, name)
        if addr != self.ida.idc.BADADDR:
            return Symbol(
                address=addr,
                name=name,
                symbol_type=self._get_symbol_type(addr),
                _manager=self,
                _native=None
            )
        return None
    
    def get_variables(self, scope: Optional[int] = None) -> List[Variable]:
        """Get variables (optionally scoped to function)."""
        variables = []
        
        try:
            if scope is not None:
                # Get variables for specific function
                # Convert to proper IDA address type
                func = self.ida.ida_funcs.get_func(int(scope))
                if func:
                    variables.extend(self._get_function_variables(func))
            else:
                # Get variables from all functions (limit to first 10 for performance)
                count = 0
                for func_ea in self.ida.idautils.Functions():
                    if count >= 10:  # Limit for performance
                        break
                    func = self.ida.ida_funcs.get_func(func_ea)
                    if func:
                        variables.extend(self._get_function_variables(func))
                        count += 1
        except Exception as e:
            # Variable analysis can be fragile, return empty list on error
            pass
        
        return variables
    
    def _get_function_variables(self, func) -> List[Variable]:
        """Get variables for a specific function."""
        variables = []
        
        try:
            # Simple approach: analyze function's disassembly for variable references
            # This is more reliable than frame analysis across IDA versions
            
            # Add some common variables based on function analysis
            func_name = self.ida.ida_name.get_name(func.start_ea)
            if func_name:
                # Add a placeholder variable representing function locals
                variables.append(Variable(
                    name=f"locals_{func_name}",
                    var_type="local_frame",
                    scope=func.start_ea,
                    size=func.size(),
                    _manager=self,
                    _native=None
                ))
            
            # Try to get actual local variables if possible
            try:
                frame = self.ida.ida_frame.get_frame(func.start_ea)
                if frame:
                    frame_size = self.ida.ida_struct.get_struc_size(frame)
                    if frame_size > 0:
                        variables.append(Variable(
                            name="stack_frame",
                            var_type="stack",
                            scope=func.start_ea,
                            size=frame_size,
                            _manager=self,
                            _native=frame
                        ))
            except Exception:
                pass
                
        except Exception:
            # If all else fails, return empty list
            pass
        
        return variables
    
    def _get_member_type(self, member) -> str:
        """Get type name for a frame member."""
        try:
            # Try to get type info from member
            member_type = self.ida.ida_struct.get_member_tinfo(member)
            if member_type:
                type_name = str(member_type)
                if type_name and type_name != "?":
                    return type_name
            
            # Fallback to size-based type guessing
            size = self.ida.ida_struct.get_member_size(member)
            if size == 1:
                return "char"
            elif size == 2:
                return "short"
            elif size == 4:
                return "int"
            elif size == 8:
                return "long long"
            else:
                return f"unknown[{size}]"
        except Exception:
            return "unknown"
    
    def get_types(self) -> List[Type]:
        """Get type information."""
        types = []
        
        try:
            # Get all defined structures
            for struct_idx in range(self.ida.ida_struct.get_struc_qty()):
                struct_id = self.ida.ida_struct.get_struc_by_idx(struct_idx)
                if struct_id != self.ida.idc.BADADDR:
                    struct = self.ida.ida_struct.get_struc(struct_id)
                    if struct:
                        name = self.ida.ida_struct.get_struc_name(struct_id)
                        size = self.ida.ida_struct.get_struc_size(struct)
                        
                        # Determine structure kind
                        if self.ida.ida_struct.is_union(struct_id):
                            kind = "union"
                        else:
                            kind = "struct"
                        
                        types.append(Type(
                            name=name or f"struct_{struct_id:x}",
                            size=size,
                            kind=kind
                        ))
        except Exception:
            # Type enumeration can fail, continue
            pass
        
        try:
            # Get enums
            for enum_idx in range(self.ida.ida_enum.get_enum_qty()):
                enum_id = self.ida.ida_enum.getn_enum(enum_idx)
                if enum_id != self.ida.idc.BADADDR:
                    name = self.ida.ida_enum.get_enum_name(enum_id)
                    # Enums don't have a fixed size, estimate
                    size = 4  # Most enums are int-sized
                    
                    types.append(Type(
                        name=name or f"enum_{enum_id:x}",
                        size=size,
                        kind="enum"
                    ))
        except Exception:
            pass
        
        # Add basic primitive types
        primitive_types = [
            ("char", 1, "primitive"),
            ("short", 2, "primitive"),
            ("int", 4, "primitive"),
            ("long", 8, "primitive"),
            ("float", 4, "primitive"),
            ("double", 8, "primitive"),
            ("void*", 8, "primitive"),  # Assume 64-bit
        ]
        
        for name, size, kind in primitive_types:
            types.append(Type(name=name, size=size, kind=kind))
        
        return types
    
    def get_strings(self) -> List[Symbol]:
        """Get string literals."""
        strings = []
        # Get string literals from IDA
        for seg_ea in self.ida.idautils.Segments():
            seg = self.ida.ida_segment.getseg(seg_ea)
            if seg:
                for head in self.ida.idautils.Heads(seg.start_ea, seg.end_ea):
                    if self.ida.ida_bytes.is_strlit(self.ida.ida_bytes.get_flags(head)):
                        str_type = self.ida.ida_nalt.get_str_type(head)
                        if str_type != self.ida.ida_nalt.STRTYPE_C:
                            continue
                        length = self.ida.ida_bytes.get_max_strlit_length(head, str_type)
                        if length > 0:
                            name = self.ida.ida_bytes.get_strlit_contents(head, length, str_type)
                            if name:
                                strings.append(Symbol(
                                    address=head,
                                    name=name.decode('utf-8', errors='ignore'),
                                    symbol_type="string"
                                ))
        return strings
    
    def _get_symbol_type(self, addr: int) -> str:
        """Get symbol type."""
        if self.ida.ida_funcs.get_func(addr):
            return "function"
        elif self.ida.idc.is_data(self.ida.idc.get_full_flags(addr)):
            return "data"
        else:
            return "unknown"


class IdaBinaryManager(BinaryManager):
    """IDA binary file format implementation."""
    
    def __init__(self, ida_native, analyzer=None):
        self.ida = ida_native
        self._analyzer = analyzer
    
    def get_segments(self) -> List[dict]:
        """Get memory segments."""
        segments = []
        for seg_ea in self.ida.idautils.Segments():
            seg = self.ida.ida_segment.getseg(seg_ea)
            if seg:
                segments.append({
                    "name": self.ida.ida_segment.get_segm_name(seg),
                    "start": seg.start_ea,
                    "end": seg.end_ea,
                    "size": seg.size(),
                    "permissions": seg.perm
                })
        return segments
    
    def get_sections(self) -> List[dict]:
        """Get file sections."""
        # IDA doesn't have direct section access like PE/ELF parsers
        # Return segments as sections
        return self.get_segments()
    
    def get_imports(self) -> List[Symbol]:
        """Get imported functions/symbols."""
        imports = []
        nimps = self.ida.ida_nalt.get_import_module_qty()
        for i in range(nimps):
            name = self.ida.ida_nalt.get_import_module_name(i)
            if name:
                def imp_cb(ea, name, ord):
                    imports.append(Symbol(
                        address=ea,
                        name=name,
                        symbol_type="import",
                        _manager=None,  # Not strictly a symbol manager object
                        _native=None
                    ))
                    return True
                self.ida.ida_nalt.enum_import_names(i, imp_cb)
        return imports
    
    def get_exports(self) -> List[Symbol]:
        """Get exported functions/symbols."""
        exports = []
        for i in range(self.ida.ida_entry.get_entry_qty()):
            ord = self.ida.ida_entry.get_entry_ordinal(i)
            ea = self.ida.ida_entry.get_entry(ord)
            name = self.ida.ida_entry.get_entry_name(ord)
            if ea != self.ida.idc.BADADDR:
                exports.append(Symbol(
                    address=ea,
                    name=name or f"export_{ord}",
                    symbol_type="export",
                    _manager=None,  # Not strictly a symbol manager object
                    _native=None
                ))
        return exports
    
    def get_entry_points(self) -> List[int]:
        """Get program entry points."""
        entry_points = []
        for i in range(self.ida.ida_entry.get_entry_qty()):
            ord = self.ida.ida_entry.get_entry_ordinal(i)
            ea = self.ida.ida_entry.get_entry(ord)
            if ea != self.ida.idc.BADADDR:
                entry_points.append(ea)
        return entry_points
    
    def get_file_info(self) -> dict:
        """Get file format information."""
        try:
            # Try to get basic file info with safe IDA API calls
            filename = self.ida.ida_nalt.get_root_filename()
            base_addr = self.ida.ida_nalt.get_imagebase()
            arch = self.ida.ida_idp.get_idp_name() if hasattr(self.ida.ida_idp, 'get_idp_name') else "unknown"
            
            # Use idc for more reliable info
            bits = 64 if self.ida.idc.get_inf_attr(self.ida.idc.INF_LFLAGS) & self.ida.idc.LFLG_64BIT else 32
            
            return {
                "filename": filename,
                "filetype": "unknown",  # Skip complex filetype detection for now
                "architecture": arch,
                "bits": bits,
                "endian": "little",  # Default assumption
                "base_address": base_addr
            }
        except Exception as e:
            # Fallback to minimal info
            return {
                "filename": "unknown",
                "filetype": "unknown",
                "architecture": "unknown", 
                "bits": 32,
                "endian": "little",
                "base_address": 0
            }