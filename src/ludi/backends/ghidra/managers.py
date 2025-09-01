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
from ..base.types import Function, Instruction, Symbol, Type, Variable, XRef


class GhidraFunctionManager(FunctionManager):
    def __init__(self, ghidra_native, analyzer=None):
        self.ghidra = ghidra_native
        self._analyzer = analyzer
        self._functions_cache = None

    def available_levels(self) -> list[str]:
        return ["disassembly", "pcode", "pseudocode"]

    def all(self, level: Optional[str] = None) -> list[Function]:
        if self._functions_cache is None:
            self._load_functions()

        functions = []
        for func_data in self._functions_cache.get("functions", []):
            functions.append(
                Function(
                    start=int(func_data["start"], 16),
                    end=int(func_data["end"], 16),
                    name=func_data.get("name"),
                    size=func_data.get("size"),
                    level=level or "disassembly",
                    _manager=self,
                    _native=func_data,
                )
            )
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
        return self.function_containing(addr, level)

    def function_containing(
        self, addr: int, level: Optional[str] = None
    ) -> Optional[Function]:
        for func in self.all(level):
            if func.start <= addr < func.end:
                return func
        return None

    def decompiled_code(self, addr: int, level: Optional[str] = None) -> Optional[str]:
        func = self.function_containing(addr)
        if not func:
            return None

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

    def instructions(
        self, addr: int, count: int = 10, level: Optional[str] = None
    ) -> list[Instruction]:
        try:
            script_content = f"""
//@category LUDI
import ghidra.program.model.listing.Instruction;

public void run() throws Exception {{
    ghidra.program.model.address.Address addr = toAddr(0x{addr:x});
    for (int i = 0; i < {count}; i++) {{
        Instruction instr = getInstructionAt(addr);
        if (instr == null) break;
        println(instr.getAddress() + ":" + instr.getMnemonicString() + ":" + instr.getDefaultOperandRepresentation(0));
        addr = instr.getAddress().add(instr.getLength());
    }}
}}
"""
            result = self.ghidra._run_script(script_content, "instructions")
            instructions = []

            if result:
                for line in result.strip().split("\n"):
                    if ":" in line:
                        parts = line.split(":", 2)
                        if len(parts) >= 2:
                            addr_str = parts[0]
                            mnemonic = parts[1]
                            operand = parts[2] if len(parts) > 2 else ""

                            try:
                                instr_addr = int(addr_str, 16)
                                instructions.append(
                                    Instruction(
                                        address=instr_addr,
                                        mnemonic=mnemonic,
                                        operands=[operand] if operand else [],
                                        level=level or "disassembly",
                                        _native=None,
                                    )
                                )
                            except ValueError:
                                continue

            return instructions
        except Exception:
            return []

    def _load_functions(self):
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
            self._functions_cache = {"functions": []}

            if result:
                lines = result.strip().split("\n")
                current_func = {}

                for line in lines:
                    line = line.strip()
                    if line == "{":
                        current_func = {}
                    elif line == "},":
                        if current_func:
                            self._functions_cache["functions"].append(current_func)
                            current_func = {}
                    elif ":" in line:
                        parts = line.split(":", 1)
                        if len(parts) == 2:
                            key = parts[0].strip().strip('"')
                            value = parts[1].strip().rstrip(",").strip('"')
                            if key in ["size"]:
                                try:
                                    value = int(value)
                                except ValueError:
                                    pass
                            current_func[key] = value
        except Exception:
            self._functions_cache = {"functions": []}


class GhidraXRefManager(XRefManager):
    def __init__(self, ghidra_native, analyzer=None):
        self.ghidra = ghidra_native
        self._analyzer = analyzer

    def xrefs_to(self, addr: int) -> list[XRef]:
        try:
            script_content = f"""
//@category LUDI
import ghidra.program.model.symbol.Reference;

public void run() throws Exception {{
    for (Reference ref : getReferencesTo(toAddr(0x{addr:x}))) {{
        println(ref.getFromAddress() + ":" + ref.getToAddress() + ":" + ref.getReferenceType());
    }}
}}
"""
            result = self.ghidra._run_script(script_content, "xrefs_to")
            xrefs = []

            if result:
                for line in result.strip().split("\n"):
                    if ":" in line:
                        parts = line.split(":", 2)
                        if len(parts) >= 3:
                            try:
                                from_addr = int(parts[0], 16)
                                to_addr = int(parts[1], 16)
                                ref_type = parts[2].lower()

                                xrefs.append(
                                    XRef(
                                        from_addr=from_addr,
                                        to_addr=to_addr,
                                        xref_type=ref_type,
                                        _manager=self,
                                        _native=None,
                                    )
                                )
                            except ValueError:
                                continue

            return xrefs
        except Exception:
            return []

    def xrefs_from(self, addr: int) -> list[XRef]:
        try:
            script_content = f"""
//@category LUDI
import ghidra.program.model.symbol.Reference;

public void run() throws Exception {{
    for (Reference ref : getReferencesFrom(toAddr(0x{addr:x}))) {{
        println(ref.getFromAddress() + ":" + ref.getToAddress() + ":" + ref.getReferenceType());
    }}
}}
"""
            result = self.ghidra._run_script(script_content, "xrefs_from")
            xrefs = []

            if result:
                for line in result.strip().split("\n"):
                    if ":" in line:
                        parts = line.split(":", 2)
                        if len(parts) >= 3:
                            try:
                                from_addr = int(parts[0], 16)
                                to_addr = int(parts[1], 16)
                                ref_type = parts[2].lower()

                                xrefs.append(
                                    XRef(
                                        from_addr=from_addr,
                                        to_addr=to_addr,
                                        xref_type=ref_type,
                                        _manager=self,
                                        _native=None,
                                    )
                                )
                            except ValueError:
                                continue

            return xrefs
        except Exception:
            return []


class GhidraSymbolManager(SymbolManager):
    def __init__(self, ghidra_native, analyzer=None):
        self.ghidra = ghidra_native
        self._analyzer = analyzer

    def all(self) -> list[Symbol]:
        try:
            script_content = """
//@category LUDI
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolTable;

public void run() throws Exception {
    SymbolTable st = currentProgram.getSymbolTable();

    for (Symbol symbol : st.getAllSymbols(true)) {
        println(symbol.getAddress() + ":" + symbol.getName() + ":" + symbol.getSymbolType());
    }
}
"""
            result = self.ghidra._run_script(script_content, "symbols")
            symbols = []

            if result:
                for line in result.strip().split("\n"):
                    if ":" in line:
                        parts = line.split(":", 2)
                        if len(parts) >= 3:
                            try:
                                addr = int(parts[0], 16)
                                name = parts[1]
                                symbol_type = parts[2].lower()

                                symbols.append(
                                    Symbol(
                                        address=addr,
                                        name=name,
                                        symbol_type=symbol_type,
                                        _manager=self,
                                        _native=None,
                                    )
                                )
                            except ValueError:
                                continue

            return symbols
        except Exception:
            return []

    def by_address(self, addr: int) -> Optional[Symbol]:
        for symbol in self.all():
            if symbol.address == addr:
                return symbol
        return None

    def by_name(self, name: str) -> Optional[Symbol]:
        for symbol in self.all():
            if symbol.name == name:
                return symbol
        return None

    def variables(self, scope: Optional[int] = None) -> list[Variable]:
        return []

    def get_types(self) -> list[Type]:
        return [
            Type(name="char", size=1, kind="primitive"),
            Type(name="short", size=2, kind="primitive"),
            Type(name="int", size=4, kind="primitive"),
            Type(name="long", size=8, kind="primitive"),
            Type(name="float", size=4, kind="primitive"),
            Type(name="double", size=8, kind="primitive"),
            Type(name="void*", size=8, kind="primitive"),
        ]

    def get_strings(self) -> list[Symbol]:
        try:
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
            result = self.ghidra._run_script(script_content, "strings")
            strings = []

            if result:
                for line in result.strip().split("\n"):
                    if ":" in line:
                        parts = line.split(":", 1)
                        if len(parts) == 2:
                            try:
                                addr = int(parts[0], 16)
                                value = parts[1]
                                strings.append(
                                    Symbol(
                                        address=addr,
                                        name=value,
                                        symbol_type="string",
                                        _manager=self,
                                        _native=None,
                                    )
                                )
                            except ValueError:
                                continue

            return strings
        except Exception:
            return []


class GhidraBinaryManager(BinaryManager):
    def __init__(self, ghidra_native, analyzer=None):
        self.ghidra = ghidra_native
        self._analyzer = analyzer

    def segments(self) -> list[dict]:
        try:
            script_content = """
//@category LUDI
import ghidra.program.model.mem.MemoryBlock;

public void run() throws Exception {
    for (MemoryBlock block : currentProgram.getMemory().getBlocks()) {
        println("{");
        println("  \\"name\\": \\"" + block.getName() + "\\",");
        println("  \\"start\\": \\"" + block.getStart() + "\\",");
        println("  \\"end\\": \\"" + block.getEnd() + "\\",");
        println("  \\"size\\": " + block.getSize());
        println("},");
    }
}
"""
            result = self.ghidra._run_script(script_content, "segments")
            segments = []

            if result:
                lines = result.strip().split("\n")
                current_segment = {}

                for line in lines:
                    line = line.strip()
                    if line == "{":
                        current_segment = {}
                    elif line == "},":
                        if current_segment:
                            if "start" in current_segment:
                                current_segment["start"] = int(
                                    current_segment["start"], 16
                                )
                            if "end" in current_segment:
                                current_segment["end"] = int(current_segment["end"], 16)
                            segments.append(current_segment)
                            current_segment = {}
                    elif ":" in line:
                        parts = line.split(":", 1)
                        if len(parts) == 2:
                            key = parts[0].strip().strip('"')
                            value = parts[1].strip().rstrip(",").strip('"')
                            if key in ["size"]:
                                try:
                                    value = int(value)
                                except ValueError:
                                    pass
                            current_segment[key] = value

            return segments
        except Exception:
            return []

    def sections(self) -> list[dict]:
        return self.segments()

    def imports(self) -> list[Symbol]:
        try:
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
            result = self.ghidra._run_script(script_content, "imports")
            imports = []

            if result:
                for line in result.strip().split("\n"):
                    if ":" in line:
                        parts = line.split(":", 2)
                        if len(parts) >= 2:
                            try:
                                addr = int(parts[0], 16)
                                name = parts[1]
                                imports.append(
                                    Symbol(
                                        address=addr,
                                        name=name,
                                        symbol_type="import",
                                        _manager=None,
                                        _native=None,
                                    )
                                )
                            except ValueError:
                                continue

            return imports
        except Exception:
            return []

    def entry_points(self) -> list[int]:
        try:
            script_content = """
//@category LUDI
import ghidra.program.model.address.AddressSetView;

public void run() throws Exception {
    AddressSetView entryPoints = currentProgram.getSymbolTable().getExternalEntryPointIterator();
    for (ghidra.program.model.address.Address addr : entryPoints) {
        println(addr.toString());
    }
}
"""
            result = self.ghidra._run_script(script_content, "entry_points")
            entry_points = []

            if result:
                for line in result.strip().split("\n"):
                    if line:
                        try:
                            addr = int(line, 16)
                            entry_points.append(addr)
                        except ValueError:
                            continue

            return entry_points
        except Exception:
            return []

    @property
    def file_info(self) -> dict:
        try:
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
            result = self.ghidra._run_script(script_content, "file_info")
            info = {}

            if result:
                for line in result.strip().split("\n"):
                    if ":" in line:
                        parts = line.split(":", 1)
                        if len(parts) == 2:
                            key = parts[0]
                            value = parts[1]
                            if key == "bits":
                                try:
                                    value = int(value)
                                except ValueError:
                                    pass
                            info[key] = value

            return info
        except Exception:
            return {}


class GhidraTypeManager(TypeManager):
    def __init__(self, ghidra_native, analyzer=None):
        self.ghidra = ghidra_native
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


class GhidraArchitectureManager(ArchitectureManager):
    def __init__(self, ghidra_native, analyzer=None):
        self.ghidra = ghidra_native
        self._analyzer = analyzer

    @property
    def name(self) -> str:
        try:
            script_content = """
//@category LUDI
public void run() throws Exception {
    println("arch:" + currentProgram.getLanguage().getProcessor().toString());
}
"""
            result = self.ghidra._run_script(script_content, "arch")
            if result and "arch:" in result:
                return result.split("arch:")[-1].strip().lower()
        except Exception:
            pass
        return "unknown"

    @property
    def bits(self) -> int:
        try:
            script_content = """
//@category LUDI
public void run() throws Exception {
    println("bits:" + currentProgram.getAddressFactory().getDefaultAddressSpace().getSize());
}
"""
            result = self.ghidra._run_script(script_content, "bits")
            if result and "bits:" in result:
                return int(result.split("bits:")[-1].strip())
        except Exception:
            pass
        return 32

    @property
    def endian(self) -> str:
        try:
            script_content = """
//@category LUDI
public void run() throws Exception {
    println("endian:" + (currentProgram.getLanguage().isBigEndian() ? "big" : "little"));
}
"""
            result = self.ghidra._run_script(script_content, "endian")
            if result and "endian:" in result:
                return result.split("endian:")[-1].strip()
        except Exception:
            pass
        return "little"

    def registers(self) -> list[str]:
        return []

    def get_register_info(self, name: str) -> Optional[dict]:
        return None

    def calling_convention(self) -> Optional[str]:
        return None


class GhidraMemoryManager(MemoryManager):
    def __init__(self, ghidra_native, analyzer=None):
        self.ghidra = ghidra_native
        self._analyzer = analyzer

    @property
    def base_address(self) -> int:
        try:
            script_content = """
//@category LUDI
public void run() throws Exception {
    println("base:" + currentProgram.getImageBase());
}
"""
            result = self.ghidra._run_script(script_content, "base")
            if result and "base:" in result:
                return int(result.split("base:")[-1].strip(), 16)
        except Exception:
            pass
        return 0

    def read(self, addr: int, size: int) -> Optional[bytes]:
        try:
            script_content = f"""
//@category LUDI
import ghidra.program.model.mem.Memory;

public void run() throws Exception {{
    Memory memory = currentProgram.getMemory();
    byte[] data = new byte[{size}];
    memory.getBytes(toAddr(0x{addr:x}), data);
    for (int i = 0; i < data.length; i++) {{
        printf("%02x", data[i] & 0xFF);
    }}
}}
"""
            result = self.ghidra._run_script(script_content, "read")
            if result:
                return bytes.fromhex(result.strip())
        except Exception:
            pass
        return None

    def read_string(self, addr: int, max_length: int = 1024) -> Optional[str]:
        data = self.read(addr, max_length)
        if data:
            null_pos = data.find(b"\x00")
            if null_pos != -1:
                data = data[:null_pos]
            return data.decode("utf-8", errors="ignore")
        return None

    def read_pointer(self, addr: int) -> Optional[int]:
        ptr_size = (
            self.ghidra.analyzer.architecture.bits // 8
            if hasattr(self.ghidra, "analyzer")
            else 8
        )
        data = self.read(addr, ptr_size)
        if data:
            endian = (
                self.ghidra.analyzer.architecture.endian
                if hasattr(self.ghidra, "analyzer")
                else "little"
            )
            if endian == "big":
                return int.from_bytes(data, "big")
            else:
                return int.from_bytes(data, "little")
        return None

    def is_valid_address(self, addr: int) -> bool:
        try:
            script_content = f"""
//@category LUDI
public void run() throws Exception {{
    boolean valid = currentProgram.getMemory().contains(toAddr(0x{addr:x}));
    println("valid:" + valid);
}}
"""
            result = self.ghidra._run_script(script_content, "valid")
            if result and "valid:" in result:
                return result.split("valid:")[-1].strip().lower() == "true"
        except Exception:
            pass
        return False

    def permissions(self, addr: int) -> Optional[str]:
        try:
            script_content = f"""
//@category LUDI
import ghidra.program.model.mem.MemoryBlock;

public void run() throws Exception {{
    MemoryBlock block = currentProgram.getMemory().getBlock(toAddr(0x{addr:x}));
    if (block != null) {{
        String perms = "";
        if (block.isRead()) perms += "r";
        if (block.isWrite()) perms += "w"; 
        if (block.isExecute()) perms += "x";
        println("perms:" + perms);
    }}
}}
"""
            result = self.ghidra._run_script(script_content, "perms")
            if result and "perms:" in result:
                return result.split("perms:")[-1].strip()
        except Exception:
            pass
        return None
