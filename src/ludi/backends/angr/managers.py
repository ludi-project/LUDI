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
from ..base.types import BasicBlock, Function, Instruction, Symbol, Type, Variable, XRef


class AngrFunctionManager(FunctionManager):
    def __init__(self, angr_native, analyzer=None):
        self.angr = angr_native
        self._analyzer = analyzer

    def available_levels(self) -> list[str]:
        levels = ["disassembly", "vex"]
        try:
            if hasattr(self.angr, "analyses") and hasattr(
                self.angr.analyses, "Decompiler"
            ):
                levels.append("pseudocode")
        except (AttributeError, ImportError):
            pass
        return levels

    def all(self, level: Optional[str] = None) -> list[Function]:
        functions = []

        try:
            if not hasattr(self.angr, "_cfg"):
                self.angr._cfg = self.angr.analyses.CFGFast()

            cfg = self.angr._cfg

            for _func_addr, func in cfg.functions.items():
                name = func.name if func.name else None
                size = 0
                if func.blocks:
                    addresses = [block.addr for block in func.blocks]
                    if addresses:
                        size = max(addresses) - min(addresses) + 4  # Rough estimate

                functions.append(
                    Function(
                        start=func.addr,
                        end=func.addr + size,
                        name=name,
                        size=size,
                        level=level or "disassembly",
                        _manager=self,
                        _native=func,
                    )
                )
        except Exception:
            pass

        return functions

    def by_address(self, addr: int, level: Optional[str] = None) -> Optional[Function]:
        for func in self.all(level):
            if func.start == addr:
                return func
        return None

    def by_name(self, name: str) -> Optional[Function]:
        for func in self.all():
            if func.name == name:
                return func
        return None

    def containing(self, addr: int, level: Optional[str] = None) -> Optional[Function]:
        try:
            if not hasattr(self.angr, "_cfg"):
                self.angr._cfg = self.angr.analyses.CFGFast()

            cfg = self.angr._cfg
            func = cfg.functions.floor_func(addr)

            if func and func.addr <= addr:
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
                            _native=func,
                        )
        except Exception:
            pass

        return None

    def decompiled_code(self, addr: int, level: Optional[str] = None) -> Optional[str]:
        try:
            if not hasattr(self.angr, "_cfg"):
                self.angr._cfg = self.angr.analyses.CFGFast()

            cfg = self.angr._cfg
            func = cfg.functions.get(addr)
            if not func:
                func = cfg.functions.floor_func(addr)

            if func:
                if level == "pseudocode" or level is None:
                    try:
                        if hasattr(self.angr.analyses, "Decompiler"):
                            try:
                                func.normalize()
                            except Exception:
                                pass

                            dec = self.angr.analyses.Decompiler(func, fail_fast=True)
                            if dec.codegen and dec.codegen.text:
                                return dec.codegen.text
                    except Exception:
                        pass

                if level == "disassembly" or level is None:
                    try:
                        disasm_lines = []
                        for block in func.blocks:
                            block_obj = self.angr.factory.block(
                                block.addr, size=block.size
                            )
                            for insn in block_obj.disassembly.insns:
                                disasm_lines.append(
                                    f"0x{insn.address:x}: {insn.mnemonic} {insn.op_str}"
                                )
                        return "\n".join(disasm_lines)
                    except Exception:
                        pass

                if level == "vex":
                    try:
                        vex_lines = []
                        for block in func.blocks:
                            block_obj = self.angr.factory.block(
                                block.addr, size=block.size
                            )
                            vex_lines.append(f"Block 0x{block.addr:x}:")
                            vex_lines.append(str(block_obj.vex))
                        return "\n".join(vex_lines)
                    except Exception:
                        pass
        except Exception:
            pass

        return None

    def basic_blocks(self, addr: int, level: Optional[str] = None) -> list[BasicBlock]:
        try:
            if not hasattr(self.angr, "_cfg"):
                self.angr._cfg = self.angr.analyses.CFGFast()

            cfg = self.angr._cfg
            func = cfg.functions.get(addr)
            if not func:
                func = cfg.functions.floor_func(addr)

            if func:
                blocks = []
                for block in func.blocks:
                    instructions = []
                    try:
                        block_obj = self.angr.factory.block(block.addr, size=block.size)
                        for insn in block_obj.disassembly.insns:
                            instructions.append(
                                Instruction(
                                    address=insn.address,
                                    mnemonic=insn.mnemonic,
                                    operands=[insn.op_str] if insn.op_str else [],
                                    level=level or "disassembly",
                                    _native=insn,
                                )
                            )
                    except Exception:
                        instructions.append(
                            Instruction(
                                address=block.addr,
                                mnemonic="unknown",
                                operands=[],
                                level=level or "disassembly",
                                _native=None,
                            )
                        )

                    blocks.append(
                        BasicBlock(
                            start=block.addr,
                            end=block.addr + block.size,
                            instructions=instructions,
                            size=block.size,
                            level=level or "disassembly",
                            _native=block,
                        )
                    )

                return blocks
        except Exception:
            pass

        return []

    def instructions(self, addr: int, level: Optional[str] = None) -> list[Instruction]:
        instructions = []
        for block in self.basic_blocks(addr, level):
            instructions.extend(block.instructions)
        return instructions

    def cfg(self, addr: int):
        return None

    def call_graph(self):
        return None

    def representation(self, addr: int, level: str = "disasm") -> Optional[str]:
        return self.decompiled_code(addr, level)

    def string_references(self, addr: int) -> list[tuple]:
        return []


class AngrXRefManager(XRefManager):
    def __init__(self, angr_native, analyzer=None):
        self.angr = angr_native
        self._analyzer = analyzer

    def xrefs_to(self, addr: int) -> list[XRef]:
        xrefs = []

        try:
            if not hasattr(self.angr, "_cfg"):
                self.angr._cfg = self.angr.analyses.CFGFast()

            cfg = self.angr._cfg

            for _func_addr, func in cfg.functions.items():
                for block in func.blocks:
                    try:
                        block_obj = self.angr.factory.block(block.addr, size=block.size)
                        for insn in block_obj.disassembly.insns:
                            if insn.op_str and hex(addr) in insn.op_str:
                                xref_type = (
                                    "call"
                                    if "call" in insn.mnemonic.lower()
                                    else "data"
                                )
                                xrefs.append(
                                    XRef(
                                        from_addr=insn.address,
                                        to_addr=addr,
                                        xref_type=xref_type,
                                        _manager=self,
                                        _native=None,
                                    )
                                )
                    except Exception:
                        continue
        except Exception:
            pass

        return xrefs

    def xrefs_from(self, addr: int) -> list[XRef]:
        xrefs = []

        try:
            if not hasattr(self.angr, "_cfg"):
                self.angr._cfg = self.angr.analyses.CFGFast()

            cfg = self.angr._cfg

            func = cfg.functions.floor_func(addr)
            if func:
                for block in func.blocks:
                    if block.addr <= addr < block.addr + block.size:
                        try:
                            block_obj = self.angr.factory.block(
                                block.addr, size=block.size
                            )
                            for insn in block_obj.disassembly.insns:
                                if insn.address == addr:
                                    if insn.op_str:
                                        import re

                                        addr_matches = re.findall(
                                            r"0x[0-9a-fA-F]+", insn.op_str
                                        )
                                        for addr_str in addr_matches:
                                            try:
                                                target_addr = int(addr_str, 16)
                                                xref_type = (
                                                    "call"
                                                    if "call" in insn.mnemonic.lower()
                                                    else "data"
                                                )
                                                xrefs.append(
                                                    XRef(
                                                        from_addr=addr,
                                                        to_addr=target_addr,
                                                        xref_type=xref_type,
                                                        _manager=self,
                                                        _native=None,
                                                    )
                                                )
                                            except ValueError:
                                                continue
                                    break
                        except Exception:
                            continue
                        break
        except Exception:
            pass

        return xrefs

    def all(self) -> list[XRef]:
        return []

    def call_graph(self) -> dict:
        call_graph = {}

        try:
            if not hasattr(self.angr, "_cfg"):
                self.angr._cfg = self.angr.analyses.CFGFast()

            cfg = self.angr._cfg

            for func_addr, func in cfg.functions.items():
                calls = []
                for callsite in func.get_call_sites():
                    target = func.get_call_target(callsite)
                    if target:
                        calls.append(target)
                call_graph[func_addr] = calls
        except Exception:
            pass

        return call_graph

    def data_flow(self, addr: int) -> dict:
        return {"reads": [], "writes": [], "uses": []}


class AngrSymbolManager(SymbolManager):
    def __init__(self, angr_native, analyzer=None):
        self.angr = angr_native
        self._analyzer = analyzer

    def all(self) -> list[Symbol]:
        symbols = []

        try:
            for name, symbol in self.angr.loader.main_object.symbols_by_name.items():
                if symbol.is_function:
                    symbol_type = "function"
                else:
                    symbol_type = "data"

                symbols.append(
                    Symbol(
                        address=symbol.rebased_addr,
                        name=name,
                        symbol_type=symbol_type,
                        size=symbol.size if hasattr(symbol, "size") else None,
                        _manager=self,
                        _native=symbol,
                    )
                )
        except Exception:
            pass

        return symbols

    def by_address(self, addr: int) -> Optional[Symbol]:
        try:
            symbol = self.angr.loader.find_symbol(addr)
            if symbol:
                symbol_type = "function" if symbol.is_function else "data"
                return Symbol(
                    address=symbol.rebased_addr,
                    name=symbol.name,
                    symbol_type=symbol_type,
                    size=symbol.size if hasattr(symbol, "size") else None,
                    _manager=self,
                    _native=symbol,
                )
        except Exception:
            pass

        return None

    def by_name(self, name: str) -> Optional[Symbol]:
        try:
            symbol = self.angr.loader.find_symbol(name)
            if symbol:
                symbol_type = "function" if symbol.is_function else "data"
                return Symbol(
                    address=symbol.rebased_addr,
                    name=symbol.name,
                    symbol_type=symbol_type,
                    size=symbol.size if hasattr(symbol, "size") else None,
                    _manager=self,
                    _native=symbol,
                )
        except Exception:
            pass

        return None

    def variables(self, scope: Optional[int] = None) -> list[Variable]:
        return []

    def types(self) -> list[Type]:
        return [
            Type(name="char", size=1, kind="primitive"),
            Type(name="short", size=2, kind="primitive"),
            Type(name="int", size=4, kind="primitive"),
            Type(name="long", size=8, kind="primitive"),
            Type(name="float", size=4, kind="primitive"),
            Type(name="double", size=8, kind="primitive"),
            Type(name="void*", size=8, kind="primitive"),
        ]

    def strings(self) -> list[Symbol]:
        strings = []

        try:
            for section in self.angr.loader.main_object.sections:
                if section.is_readable and not section.is_executable:
                    try:
                        data = self.angr.loader.memory.load(
                            section.vaddr, section.memsize
                        )
                        current_string = b""
                        string_start = section.vaddr

                        for i, byte in enumerate(data):
                            if 32 <= byte <= 126:  # Printable ASCII
                                current_string += bytes([byte])
                            else:
                                if len(current_string) >= 4:  # Minimum string length
                                    strings.append(
                                        Symbol(
                                            address=string_start,
                                            name=current_string.decode(
                                                "ascii", errors="ignore"
                                            ),
                                            symbol_type="string",
                                            size=len(current_string),
                                            _manager=self,
                                            _native=None,
                                        )
                                    )
                                current_string = b""
                                string_start = section.vaddr + i + 1

                        if len(current_string) >= 4:
                            strings.append(
                                Symbol(
                                    address=string_start,
                                    name=current_string.decode(
                                        "ascii", errors="ignore"
                                    ),
                                    symbol_type="string",
                                    size=len(current_string),
                                    _manager=self,
                                    _native=None,
                                )
                            )
                    except Exception:
                        continue
        except Exception:
            pass

        return strings


class AngrBinaryManager(BinaryManager):
    def __init__(self, angr_native, analyzer=None):
        self.angr = angr_native
        self._analyzer = analyzer

    def segments(self) -> list[dict]:
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

                segments.append(
                    {
                        "name": section.name,
                        "start": section.vaddr,
                        "end": section.vaddr + section.memsize,
                        "size": section.memsize,
                        "permissions": permissions,
                    }
                )
        except Exception:
            pass

        return segments

    def sections(self) -> list[dict]:
        return self.segments()  # Same as segments for angr

    def imports(self) -> list[Symbol]:
        imports = []

        try:
            for name, symbol in self.angr.loader.main_object.symbols_by_name.items():
                if symbol.is_import:
                    imports.append(
                        Symbol(
                            address=symbol.rebased_addr,
                            name=name,
                            symbol_type="import",
                            _manager=None,
                            _native=symbol,
                        )
                    )
        except Exception:
            pass

        return imports

    def exports(self) -> list[Symbol]:
        exports = []

        try:
            for name, symbol in self.angr.loader.main_object.symbols_by_name.items():
                if symbol.is_export:
                    exports.append(
                        Symbol(
                            address=symbol.rebased_addr,
                            name=name,
                            symbol_type="export",
                            _manager=None,
                            _native=symbol,
                        )
                    )
        except Exception:
            pass

        return exports

    def entry_points(self) -> list[int]:
        try:
            return [self.angr.entry]
        except Exception:
            return []

    @property
    def file_info(self) -> dict:
        try:
            main_obj = self.angr.loader.main_object

            arch_map = {
                "X86": "x86",
                "AMD64": "x86_64",
                "ARM": "arm",
                "AARCH64": "aarch64",
                "MIPS32": "mips",
                "MIPS64": "mips64",
            }

            arch_name = arch_map.get(main_obj.arch.name, main_obj.arch.name.lower())

            return {
                "filename": main_obj.binary,
                "filetype": main_obj.os,
                "architecture": arch_name,
                "bits": main_obj.arch.bits,
                "endian": "big"
                if main_obj.arch.memory_endness == "Iend_BE"
                else "little",
                "base_address": main_obj.min_addr,
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
        if self._analyzer and hasattr(self._analyzer, "symbols"):
            return self._analyzer.symbols.strings()
        return []

    def search_strings(self, pattern: str) -> list[Symbol]:
        import re

        all_strings = self.strings()
        compiled_pattern = re.compile(pattern, re.IGNORECASE)
        return [s for s in all_strings if compiled_pattern.search(s.name)]


class AngrTypeManager(TypeManager):
    def __init__(self, angr_native, analyzer=None):
        self.angr = angr_native
        self._analyzer = analyzer

    def all(self) -> list[Type]:
        return [
            Type(name="char", size=1, kind="primitive"),
            Type(name="short", size=2, kind="primitive"),
            Type(name="int", size=4, kind="primitive"),
            Type(name="long", size=8, kind="primitive"),
            Type(name="float", size=4, kind="primitive"),
            Type(name="double", size=8, kind="primitive"),
            Type(name="void*", size=8, kind="primitive"),
        ]

    def by_name(self, name: str) -> Optional[Type]:
        for t in self.all():
            if t.name == name:
                return t
        return None

    def function_signature(self, addr: int) -> Optional[Type]:
        return None

    def primitive_types(self) -> list[Type]:
        return self.all()

    def user_types(self) -> list[Type]:
        return []


class AngrArchitectureManager(ArchitectureManager):
    def __init__(self, angr_native, analyzer=None):
        self.angr = angr_native
        self._analyzer = analyzer

    @property
    def name(self) -> str:
        try:
            main_obj = self.angr.loader.main_object
            arch_map = {
                "X86": "x86",
                "AMD64": "x86_64",
                "ARM": "arm",
                "AARCH64": "aarch64",
                "MIPS32": "mips",
                "MIPS64": "mips64",
            }
            return arch_map.get(main_obj.arch.name, main_obj.arch.name.lower())
        except Exception:
            return "unknown"

    @property
    def bits(self) -> int:
        try:
            return self.angr.loader.main_object.arch.bits
        except Exception:
            return 32

    @property
    def endian(self) -> str:
        try:
            main_obj = self.angr.loader.main_object
            return "big" if main_obj.arch.memory_endness == "Iend_BE" else "little"
        except Exception:
            return "little"

    def registers(self) -> list[str]:
        try:
            arch = self.angr.loader.main_object.arch
            return list(arch.registers.keys()) if hasattr(arch, "registers") else []
        except Exception:
            return []

    def get_register_info(self, name: str) -> Optional[dict]:
        try:
            arch = self.angr.loader.main_object.arch
            if hasattr(arch, "registers") and name in arch.registers:
                reg = arch.registers[name]
                return {"offset": reg[0], "size": reg[1]}
        except Exception:
            pass
        return None

    def calling_convention(self) -> Optional[str]:
        try:
            arch = self.angr.loader.main_object.arch
            return getattr(arch, "calling_convention", None)
        except Exception:
            return None


class AngrMemoryManager(MemoryManager):
    def __init__(self, angr_native, analyzer=None):
        self.angr = angr_native
        self._analyzer = analyzer

    @property
    def base_address(self) -> int:
        try:
            return self.angr.loader.main_object.min_addr
        except Exception:
            return 0

    def read(self, addr: int, size: int) -> Optional[bytes]:
        try:
            return self.angr.loader.memory.load(addr, size)
        except Exception:
            return None

    def read_string(self, addr: int, max_length: int = 1024) -> Optional[str]:
        try:
            data = self.angr.loader.memory.load(addr, max_length)
            # Find null terminator
            null_pos = data.find(b"\x00")
            if null_pos != -1:
                data = data[:null_pos]
            return data.decode("utf-8", errors="ignore")
        except Exception:
            return None

    def read_pointer(self, addr: int) -> Optional[int]:
        try:
            arch = self.angr.loader.main_object.arch
            ptr_size = arch.bits // 8
            data = self.angr.loader.memory.load(addr, ptr_size)
            if arch.memory_endness == "Iend_BE":
                return int.from_bytes(data, "big")
            else:
                return int.from_bytes(data, "little")
        except Exception:
            return None

    def is_valid_address(self, addr: int) -> bool:
        try:
            return self.angr.loader.main_object.contains_addr(addr)
        except Exception:
            return False

    def permissions(self, addr: int) -> Optional[str]:
        try:
            for section in self.angr.loader.main_object.sections:
                if section.vaddr <= addr < section.vaddr + section.memsize:
                    perms = ""
                    if section.is_readable:
                        perms += "r"
                    if section.is_writable:
                        perms += "w"
                    if section.is_executable:
                        perms += "x"
                    return perms
        except Exception:
            pass
        return None
