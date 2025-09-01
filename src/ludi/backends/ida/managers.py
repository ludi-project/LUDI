from typing import Optional

from ..base.managers import (
    ArchitectureManager,
    BinaryManager,
    FunctionManager,
    MemoryManager,
    SymbolManager,
    TypeManager,
    XRefManager,
)
from ..base.types import CFG, CallGraph
from ..base.types import BasicBlock, Function, Instruction, Symbol, Type, Variable, XRef


class IdaFunctionManager(FunctionManager):
    def __init__(self, ida_native, analyzer=None):
        self.ida = ida_native
        self._analyzer = analyzer

    def available_levels(self) -> list[str]:
        levels = ["disassembly"]
        try:
            if (
                hasattr(self.ida, "ida_hexrays")
                and self.ida.ida_hexrays.init_hexrays_plugin()
            ):
                levels.extend(["microcode", "pseudocode"])
        except (AttributeError, RuntimeError):
            pass
        return levels

    def all(self, level: Optional[str] = None) -> list[Function]:
        functions = []
        for func_ea in self.ida.idautils.Functions():
            func = self.ida.ida_funcs.get_func(func_ea)
            if func:
                name = self.ida.ida_name.get_name(func.start_ea)
                functions.append(
                    Function(
                        start=func.start_ea,
                        end=func.end_ea,
                        name=name if name else None,
                        size=func.size(),
                        level=level or "disassembly",
                        _manager=self,
                        _native=func,
                    )
                )
        return functions

    def by_address(self, addr: int, level: Optional[str] = None) -> Optional[Function]:
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
                _native=func,
            )
        return None

    def by_name(self, name: str) -> Optional[Function]:
        addr = self.ida.ida_name.get_name_ea(self.ida.idc.BADADDR, name)
        if addr != self.ida.idc.BADADDR:
            return self.by_address(addr)

        return None

    def containing(self, addr: int, level: Optional[str] = None) -> Optional[Function]:
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
                _native=func,
            )
        return None

    def decompiled_code(self, addr: int, level: Optional[str] = None) -> Optional[str]:
        func = self.ida.ida_funcs.get_func(addr)
        if not func:
            return None

        if level == "pseudocode" or level is None:
            try:
                if (
                    hasattr(self.ida, "ida_hexrays")
                    and self.ida.ida_hexrays.init_hexrays_plugin()
                ):
                    cfunc = self.ida.ida_hexrays.decompile(func.start_ea)
                    if cfunc:
                        return str(cfunc)
            except Exception:
                pass

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

    def basic_blocks(self, addr: int, level: Optional[str] = None) -> list[BasicBlock]:
        func = self.ida.ida_funcs.get_func(addr)
        if not func:
            return []

        blocks = []
        instr_addrs = list(func.code_items())
        flowchart = self.ida.ida_gdl.FlowChart(f=func, flags=self.ida.ida_gdl.FC_PREDS)

        for block in flowchart:
            block_instr_addrs = [
                ea for ea in instr_addrs if block.start_ea <= ea < block.end_ea
            ]

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

                instructions.append(
                    Instruction(
                        address=ea,
                        mnemonic=mnemonic,
                        operands=operands,
                        level=level or "disassembly",
                        _native=None,  # IDA doesn't have instruction objects
                    )
                )

            blocks.append(
                BasicBlock(
                    start=block.start_ea,
                    end=block.end_ea,
                    instructions=instructions,
                    size=block.end_ea - block.start_ea,
                    level=level or "disassembly",
                    _native=block,
                )
            )

        return blocks

    def instructions(self, addr: int, level: Optional[str] = None) -> list[Instruction]:
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

            instructions.append(
                Instruction(
                    address=ea,
                    mnemonic=mnemonic,
                    operands=operands,
                    level=level or "disassembly",
                    _native=None,  # IDA doesn't have instruction objects
                )
            )

        return instructions

    def cfg(self, addr: int) -> Optional["CFG"]:
        from ..base.types import CFG

        func = self.ida.ida_funcs.get_func(addr)
        if not func:
            return None

        basic_blocks = self.basic_blocks(addr)
        edges = []

        flowchart = self.ida.ida_gdl.FlowChart(f=func, flags=self.ida.ida_gdl.FC_PREDS)
        for block in flowchart:
            for succ in block.succs():
                edges.append((block.start_ea, succ.start_ea))

        return CFG(
            function_addr=func.start_ea,
            basic_blocks=basic_blocks,
            edges=edges,
            _manager=self,
            _native=flowchart,
        )

    def call_graph(self) -> Optional["CallGraph"]:
        from ..base.types import CallGraph

        functions = self.all()
        edges = []

        # Build call graph by examining each function's calls
        for func in functions:
            for ea in self.ida.idautils.FuncItems(func.start):
                for xref in self.ida.idautils.XrefsFrom(ea):
                    if xref.type in [self.ida.ida_xref.fl_CF]:  # Call flow
                        target_func = self.ida.ida_funcs.get_func(xref.to)
                        if target_func:
                            edges.append((func.start, target_func.start_ea))

        return CallGraph(functions=functions, edges=edges, _manager=self, _native=None)

    def representation(self, addr: int, level: str = "disasm") -> Optional[str]:
        if level == "disasm":
            func = self.ida.ida_funcs.get_func(addr)
            if func:
                lines = []
                for ea in self.ida.idautils.FuncItems(func.start_ea):
                    disasm = self.ida.idc.GetDisasm(ea)
                    if disasm:
                        lines.append(f"0x{ea:x}: {disasm}")
                return "\n".join(lines)
        elif level == "decompiled":
            return self.decompiled_code(addr, "pseudocode")
        elif level == "ir":
            return self.decompiled_code(addr, "microcode")
        return None

    def string_references(self, addr: int) -> list[tuple]:
        func = self.ida.ida_funcs.get_func(addr)
        if not func:
            return []

        string_refs = []
        for ea in self.ida.idautils.FuncItems(func.start_ea):
            for xref in self.ida.idautils.XrefsFrom(ea):
                if xref.type in [
                    self.ida.ida_xref.dr_R,
                    self.ida.ida_xref.dr_O,
                ]:  # Data references
                    # Check if the referenced address contains a string
                    string_val = self.ida.idc.get_strlit_contents(xref.to)
                    if string_val:
                        string_refs.append(
                            (xref.to, string_val.decode("utf-8", errors="ignore"))
                        )

        return string_refs


class IdaXRefManager(XRefManager):
    def __init__(self, ida_native, analyzer=None):
        self.ida = ida_native
        self._analyzer = analyzer

    def _xref_type_to_string(self, xref_type) -> str:
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

    def xrefs_to(self, addr: int) -> list[XRef]:
        xrefs = []
        for xref in self.ida.idautils.XrefsTo(addr):
            xrefs.append(
                XRef(
                    from_addr=xref.frm,
                    to_addr=xref.to,
                    xref_type=self._xref_type_to_string(xref.type),
                    _manager=self,
                    _native=xref,
                )
            )
        return xrefs

    def xrefs_from(self, addr: int) -> list[XRef]:
        xrefs = []
        for xref in self.ida.idautils.XrefsFrom(addr):
            xrefs.append(
                XRef(
                    from_addr=xref.frm,
                    to_addr=xref.to,
                    xref_type=self._xref_type_to_string(xref.type),
                    _manager=self,
                    _native=xref,
                )
            )
        return xrefs

    def all(self) -> list[XRef]:
        all_xrefs = []
        for func_ea in self.ida.idautils.Functions():
            func = self.ida.ida_funcs.get_func(func_ea)
            if func:
                for ea in func.code_items():
                    for xref in self.ida.idautils.XrefsFrom(ea):
                        all_xrefs.append(
                            XRef(
                                from_addr=xref.frm,
                                to_addr=xref.to,
                                xref_type=self._xref_type_to_string(xref.type),
                                _manager=self,
                                _native=xref,
                            )
                        )
        return all_xrefs

    def call_graph(self) -> dict:
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

    def data_flow(self, addr: int) -> dict:
        data_flow = {"reads": [], "writes": [], "uses": []}
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
    def __init__(self, ida_native, analyzer=None):
        self.ida = ida_native
        self._analyzer = analyzer

    def all(self) -> list[Symbol]:
        symbols = []

        for i in range(self.ida.ida_name.get_nlist_size()):
            name = self.ida.ida_name.get_nlist_name(i)
            addr = self.ida.ida_name.get_nlist_ea(i)
            if name and addr != self.ida.idc.BADADDR:
                symbol_type = self._get_symbol_type(addr)
                symbols.append(Symbol(address=addr, name=name, symbol_type=symbol_type))

        return symbols

    def by_address(self, addr: int) -> Optional[Symbol]:
        name = self.ida.ida_name.get_name(addr)
        if name:
            return Symbol(
                address=addr,
                name=name,
                symbol_type=self._get_symbol_type(addr),
                _manager=self,
                _native=None,
            )
        return None

    def by_name(self, name: str) -> Optional[Symbol]:
        addr = self.ida.ida_name.get_name_ea(self.ida.idc.BADADDR, name)
        if addr != self.ida.idc.BADADDR:
            return Symbol(
                address=addr,
                name=name,
                symbol_type=self._get_symbol_type(addr),
                _manager=self,
                _native=None,
            )
        return None

    def variables(self, scope: Optional[int] = None) -> list[Variable]:
        variables = []

        try:
            if scope is not None:
                func = self.ida.ida_funcs.get_func(int(scope))
                if func:
                    variables.extend(self._get_function_variables(func))
            else:
                count = 0
                for func_ea in self.ida.idautils.Functions():
                    if count >= 10:  # Limit for performance
                        break
                    func = self.ida.ida_funcs.get_func(func_ea)
                    if func:
                        variables.extend(self._get_function_variables(func))
                        count += 1
        except Exception:
            pass

        return variables

    def _get_function_variables(self, func) -> list[Variable]:
        variables = []

        try:
            func_name = self.ida.ida_name.get_name(func.start_ea)
            if func_name:
                variables.append(
                    Variable(
                        name=f"locals_{func_name}",
                        var_type="local_frame",
                        scope=func.start_ea,
                        size=func.size(),
                        _manager=self,
                        _native=None,
                    )
                )

            try:
                frame = self.ida.ida_frame.get_frame(func.start_ea)
                if frame:
                    frame_size = self.ida.ida_struct.get_struc_size(frame)
                    if frame_size > 0:
                        variables.append(
                            Variable(
                                name="stack_frame",
                                var_type="stack",
                                scope=func.start_ea,
                                size=frame_size,
                                _manager=self,
                                _native=frame,
                            )
                        )
            except Exception:
                pass

        except Exception:
            pass

        return variables

    def _get_member_type(self, member) -> str:
        try:
            member_type = self.ida.ida_struct.get_member_tinfo(member)
            if member_type:
                type_name = str(member_type)
                if type_name and type_name != "?":
                    return type_name

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

    def types(self) -> list[Type]:
        types = []

        try:
            for struct_idx in range(self.ida.ida_struct.get_struc_qty()):
                struct_id = self.ida.ida_struct.get_struc_by_idx(struct_idx)
                if struct_id != self.ida.idc.BADADDR:
                    struct = self.ida.ida_struct.get_struc(struct_id)
                    if struct:
                        name = self.ida.ida_struct.get_struc_name(struct_id)
                        size = self.ida.ida_struct.get_struc_size(struct)

                        if self.ida.ida_struct.is_union(struct_id):
                            kind = "union"
                        else:
                            kind = "struct"

                        types.append(
                            Type(
                                name=name or f"struct_{struct_id:x}",
                                size=size,
                                kind=kind,
                            )
                        )
        except Exception:
            pass

        try:
            for enum_idx in range(self.ida.ida_enum.get_enum_qty()):
                enum_id = self.ida.ida_enum.getn_enum(enum_idx)
                if enum_id != self.ida.idc.BADADDR:
                    name = self.ida.ida_enum.get_enum_name(enum_id)
                    size = 4  # Most enums are int-sized

                    types.append(
                        Type(name=name or f"enum_{enum_id:x}", size=size, kind="enum")
                    )
        except Exception:
            pass

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

    def strings(self) -> list[Symbol]:
        strings = []
        for seg_ea in self.ida.idautils.Segments():
            seg = self.ida.ida_segment.getseg(seg_ea)
            if seg:
                for head in self.ida.idautils.Heads(seg.start_ea, seg.end_ea):
                    if self.ida.ida_bytes.is_strlit(self.ida.ida_bytes.get_flags(head)):
                        str_type = self.ida.ida_nalt.get_str_type(head)
                        if str_type != self.ida.ida_nalt.STRTYPE_C:
                            continue
                        length = self.ida.ida_bytes.get_max_strlit_length(
                            head, str_type
                        )
                        if length > 0:
                            name = self.ida.ida_bytes.get_strlit_contents(
                                head, length, str_type
                            )
                            if name:
                                strings.append(
                                    Symbol(
                                        address=head,
                                        name=name.decode("utf-8", errors="ignore"),
                                        symbol_type="string",
                                    )
                                )
        return strings

    def _get_symbol_type(self, addr: int) -> str:
        if self.ida.ida_funcs.get_func(addr):
            return "function"
        elif self.ida.idc.is_data(self.ida.idc.get_full_flags(addr)):
            return "data"
        else:
            return "unknown"


class IdaBinaryManager(BinaryManager):
    def __init__(self, ida_native, analyzer=None):
        self.ida = ida_native
        self._analyzer = analyzer

    def segments(self) -> list[dict]:
        segments = []
        for seg_ea in self.ida.idautils.Segments():
            seg = self.ida.ida_segment.getseg(seg_ea)
            if seg:
                segments.append(
                    {
                        "name": self.ida.ida_segment.get_segm_name(seg),
                        "start": seg.start_ea,
                        "end": seg.end_ea,
                        "size": seg.size(),
                        "permissions": seg.perm,
                    }
                )
        return segments

    def sections(self) -> list[dict]:
        return self.segments()

    def imports(self) -> list[Symbol]:
        imports = []
        nimps = self.ida.ida_nalt.get_import_module_qty()
        for i in range(nimps):
            name = self.ida.ida_nalt.get_import_module_name(i)
            if name:

                def imp_cb(ea, name, ord):
                    imports.append(
                        Symbol(
                            address=ea,
                            name=name,
                            symbol_type="import",
                            _manager=None,  # Not strictly a symbol manager object
                            _native=None,
                        )
                    )
                    return True

                self.ida.ida_nalt.enum_import_names(i, imp_cb)
        return imports

    def exports(self) -> list[Symbol]:
        exports = []
        for i in range(self.ida.ida_entry.get_entry_qty()):
            ord = self.ida.ida_entry.get_entry_ordinal(i)
            ea = self.ida.ida_entry.get_entry(ord)
            name = self.ida.ida_entry.get_entry_name(ord)
            if ea != self.ida.idc.BADADDR:
                exports.append(
                    Symbol(
                        address=ea,
                        name=name or f"export_{ord}",
                        symbol_type="export",
                        _manager=None,  # Not strictly a symbol manager object
                        _native=None,
                    )
                )
        return exports

    def entry_points(self) -> list[int]:
        entry_points = []
        for i in range(self.ida.ida_entry.get_entry_qty()):
            ord = self.ida.ida_entry.get_entry_ordinal(i)
            ea = self.ida.ida_entry.get_entry(ord)
            if ea != self.ida.idc.BADADDR:
                entry_points.append(ea)
        return entry_points

    @property
    def file_info(self) -> dict:
        try:
            filename = self.ida.ida_nalt.get_root_filename()
            base_addr = self.ida.ida_nalt.get_imagebase()
            arch = (
                self.ida.ida_idp.get_idp_name()
                if hasattr(self.ida.ida_idp, "get_idp_name")
                else "unknown"
            )

            bits = (
                64
                if self.ida.idc.get_inf_attr(self.ida.idc.INF_LFLAGS)
                & self.ida.idc.LFLG_64BIT
                else 32
            )

            return {
                "filename": filename,
                "filetype": "unknown",  # Skip complex filetype detection for now
                "architecture": arch,
                "bits": bits,
                "endian": "little",  # Default assumption
                "base_address": base_addr,
            }
        except Exception:
            return {
                "filename": "unknown",
                "filetype": "unknown",
                "architecture": "unknown",
                "bits": 32,
                "endian": "little",
                "base_address": 0,
            }

    def strings(self) -> list[Symbol]:
        strings = []
        for string_info in self.ida.idautils.Strings():
            strings.append(
                Symbol(
                    address=string_info.ea,
                    name=str(string_info),
                    symbol_type="string",
                    size=string_info.length,
                    _manager=None,
                    _native=string_info,
                )
            )
        return strings

    def search_strings(self, pattern: str) -> list[Symbol]:
        import re

        all_strings = self.strings()
        compiled_pattern = re.compile(pattern, re.IGNORECASE)
        return [s for s in all_strings if compiled_pattern.search(s.name)]


class IdaTypeManager(TypeManager):
    def __init__(self, ida_native, analyzer=None):
        self.ida = ida_native
        self._analyzer = analyzer

    def all(self) -> list[Type]:
        types = []
        types.extend(self.primitive_types())
        types.extend(self.user_types())
        return types

    def by_name(self, name: str) -> Optional[Type]:
        for typ in self.all():
            if typ.name == name:
                return typ
        return None

    def function_signature(self, addr: int) -> Optional[Type]:
        func_name = self.ida.ida_funcs.get_func_name(addr)
        if not func_name:
            return None

        try:
            func_type = self.ida.idc.GetType(addr)
        except Exception:
            func_type = None
        if func_type:
            return Type(
                name=func_name,
                size=0,
                kind="function",
                _native=func_type,
            )
        return None

    def primitive_types(self) -> list[Type]:
        primitive_types = [
            Type(name="void", size=0, kind="primitive"),
            Type(name="char", size=1, kind="primitive"),
            Type(name="short", size=2, kind="primitive"),
            Type(name="int", size=4, kind="primitive"),
            Type(name="long", size=8, kind="primitive"),
            Type(name="float", size=4, kind="primitive"),
            Type(name="double", size=8, kind="primitive"),
            Type(name="pointer", size=8, kind="primitive"),
        ]
        return primitive_types

    def user_types(self) -> list[Type]:
        user_types = []
        try:
            til = self.ida.ida_typeinf.get_idati()
            if til:
                pass
        except Exception:
            pass
        return user_types


class IdaArchitectureManager(ArchitectureManager):
    def __init__(self, ida_native, analyzer=None):
        self.ida = ida_native
        self._analyzer = analyzer

    @property
    def name(self) -> str:
        try:
            return self.ida.ida_idp.get_idp_name()
        except Exception:
            return "unknown"

    @property
    def bits(self) -> int:
        try:
            return (
                64
                if self.ida.idc.get_inf_attr(self.ida.idc.INF_LFLAGS)
                & self.ida.idc.LFLG_64BIT
                else 32
            )
        except Exception:
            return 32

    @property
    def endian(self) -> str:
        try:
            return (
                "big"
                if self.ida.idc.get_inf_attr(self.ida.idc.INF_LFLAGS)
                & self.ida.idc.LFLG_MSF
                else "little"
            )
        except Exception:
            return "little"

    def registers(self) -> list[str]:
        registers = []
        try:
            for i in range(self.ida.ida_idp.ph.regs_num):
                reg_name = self.ida.ida_idp.ph.reg_names[i]
                if reg_name:
                    registers.append(reg_name)
        except Exception:
            if self.bits == 64:
                registers = [
                    "rax",
                    "rbx",
                    "rcx",
                    "rdx",
                    "rsi",
                    "rdi",
                    "rbp",
                    "rsp",
                    "r8",
                    "r9",
                    "r10",
                    "r11",
                    "r12",
                    "r13",
                    "r14",
                    "r15",
                ]
            else:
                registers = ["eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp"]
        return registers

    def get_register_info(self, name: str) -> Optional[dict]:
        try:
            reg_num = self.ida.ida_idp.str2reg(name)
            if reg_num >= 0:
                return {
                    "name": name,
                    "number": reg_num,
                    "size": self.ida.ida_idp.ph.reg_data_size(reg_num),
                }
        except Exception:
            pass
        return None

    def calling_convention(self) -> Optional[str]:
        try:
            cc = self.ida.ida_typeinf.get_cc(self.ida.ida_typeinf.CM_CC_MASK)
            if cc == self.ida.ida_typeinf.CM_CC_CDECL:
                return "cdecl"
            elif cc == self.ida.ida_typeinf.CM_CC_STDCALL:
                return "stdcall"
            elif cc == self.ida.ida_typeinf.CM_CC_FASTCALL:
                return "fastcall"
            elif cc == self.ida.ida_typeinf.CM_CC_PASCAL:
                return "pascal"
            else:
                return "unknown"
        except Exception:
            if self.bits == 64:
                return "sysv" if "linux" in self.name.lower() else "win64"
            else:
                return "cdecl"


class IdaMemoryManager(MemoryManager):
    def __init__(self, ida_native, analyzer=None):
        self.ida = ida_native
        self._analyzer = analyzer

    @property
    def base_address(self) -> int:
        try:
            return self.ida.ida_nalt.get_imagebase()
        except Exception:
            return 0

    def read(self, addr: int, size: int) -> Optional[bytes]:
        try:
            data = self.ida.ida_bytes.get_bytes(addr, size)
            return data if data else None
        except Exception:
            return None

    def read_string(self, addr: int, max_length: int = 1024) -> Optional[str]:
        try:
            string_val = self.ida.idc.get_strlit_contents(addr, max_length)
            if string_val:
                return string_val.decode("utf-8", errors="ignore")
        except Exception:
            pass

        try:
            data = self.read(addr, max_length)
            if data:
                null_pos = data.find(b"\x00")
                if null_pos >= 0:
                    data = data[:null_pos]
                return data.decode("utf-8", errors="ignore")
        except Exception:
            pass

        return None

    def read_pointer(self, addr: int) -> Optional[int]:
        try:
            if self._get_arch_bits() == 64:
                data = self.read(addr, 8)
                if data and len(data) == 8:
                    return int.from_bytes(data, byteorder="little")
            else:
                data = self.read(addr, 4)
                if data and len(data) == 4:
                    return int.from_bytes(data, byteorder="little")
        except Exception:
            pass
        return None

    def is_valid_address(self, addr: int) -> bool:
        try:
            return self.ida.ida_bytes.is_loaded(addr)
        except Exception:
            return False

    def permissions(self, addr: int) -> Optional[str]:
        return self.get_permissions(addr)

    def get_permissions(self, addr: int) -> Optional[str]:
        try:
            seg = self.ida.ida_segment.getseg(addr)
            if seg:
                perms = []
                if seg.perm & self.ida.ida_segment.SEGPERM_READ:
                    perms.append("r")
                if seg.perm & self.ida.ida_segment.SEGPERM_WRITE:
                    perms.append("w")
                if seg.perm & self.ida.ida_segment.SEGPERM_EXEC:
                    perms.append("x")
                return "".join(perms)
        except Exception:
            pass
        return None

    def _get_arch_bits(self) -> int:
        try:
            return (
                64
                if self.ida.idc.get_inf_attr(self.ida.idc.INF_LFLAGS)
                & self.ida.idc.LFLG_64BIT
                else 32
            )
        except Exception:
            return 32
