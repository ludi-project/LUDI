from typing import List, Optional

from ..base.managers import (
    BinaryManager,
    FunctionManager,
    SymbolManager,
    XRefManager,
    TypeManager,
    ArchitectureManager,
    MemoryManager,
)
from ..base.types import Function, Symbol, XRef


class RemoteFunctionManager(FunctionManager):
    def __init__(self, client):
        self.client = client

    def all(self, level: Optional[str] = None) -> list[Function]:
        return self.client.call_method("functions", "all", level=level)

    def by_address(self, addr: int, level: Optional[str] = None) -> Optional[Function]:
        return self.client.call_method("functions", "by_address", addr, level=level)

    def by_name(self, name: str) -> Optional[Function]:
        return self.client.call_method("functions", "by_name", name)

    def get_between(self, start_addr: int, end_addr: int) -> list[Function]:
        return self.client.call_method("functions", "get_between", start_addr, end_addr)

    def decompiled_code(self, addr: int, level: Optional[str] = None) -> Optional[str]:
        return self.client.call_method(
            "functions", "decompiled_code", addr, level=level
        )

    # Missing abstract methods - stub implementations
    def containing(self, addr: int, level: Optional[str] = None):
        return self.client.call_method("functions", "containing", addr, level=level)

    def basic_blocks(self, addr: int, level: Optional[str] = None):
        return self.client.call_method("functions", "basic_blocks", addr, level=level)

    def instructions(self, addr: int, level: Optional[str] = None):
        return self.client.call_method("functions", "instructions", addr, level=level)

    def available_levels(self):
        return self.client.call_method("functions", "available_levels")

    def cfg(self, addr: int):
        return self.client.call_method("functions", "cfg", addr)

    def call_graph(self):
        return self.client.call_method("functions", "call_graph")

    def representation(self, addr: int, level: str = "disasm"):
        return self.client.call_method("functions", "representation", addr, level=level)

    def string_references(self, addr: int):
        return self.client.call_method("functions", "string_references", addr)


class RemoteSymbolManager(SymbolManager):
    def __init__(self, client):
        self.client = client

    def all(self) -> list[Symbol]:
        return self.client.call_method("symbols", "all")

    def by_address(self, addr: int) -> Optional[Symbol]:
        return self.client.call_method("symbols", "by_address", addr)

    def by_name(self, name: str) -> Optional[Symbol]:
        return self.client.call_method("symbols", "by_name", name)

    # Missing abstract methods - stub implementations
    def variables(self, scope: Optional[int] = None):
        return self.client.call_method("symbols", "variables", scope=scope)

    def types(self):
        return self.client.call_method("symbols", "types")

    def strings(self):
        return self.client.call_method("symbols", "strings")


class RemoteXRefManager(XRefManager):
    def __init__(self, client):
        self.client = client

    def xrefs_to(self, addr: int) -> list[XRef]:
        return self.client.call_method("xrefs", "xrefs_to", addr)

    def xrefs_from(self, addr: int) -> list[XRef]:
        return self.client.call_method("xrefs", "xrefs_from", addr)

    # Missing abstract methods - stub implementations
    def all(self):
        return self.client.call_method("xrefs", "all")

    def call_graph(self):
        return self.client.call_method("xrefs", "call_graph")

    def data_flow(self, addr: int):
        return self.client.call_method("xrefs", "data_flow", addr)


class RemoteBinaryManager(BinaryManager):
    def __init__(self, client):
        self.client = client

    def segments(self) -> list[dict]:
        return self.client.call_method("binary", "segments")

    def sections(self) -> list[dict]:
        return self.client.call_method("binary", "sections")

    def entry_points(self) -> list[int]:
        return self.client.call_method("binary", "entry_points")

    # Missing abstract methods - need to add more based on base class
    def imports(self) -> list:
        return self.client.call_method("binary", "imports")

    def exports(self) -> list:
        return self.client.call_method("binary", "exports")

    @property
    def file_info(self) -> dict:
        return self.client.call_method("binary", "file_info")

    def strings(self) -> List:
        return self.client.call_method("binary", "strings")

    def search_strings(self, pattern: str) -> List:
        return self.client.call_method("binary", "search_strings", pattern)


class RemoteTypeManager(TypeManager):
    def __init__(self, client):
        self.client = client

    def all(self) -> List:
        return self.client.call_method("types", "all")

    def by_name(self, name: str) -> Optional:
        return self.client.call_method("types", "by_name", name)

    def function_signature(self, addr: int) -> Optional:
        return self.client.call_method("types", "function_signature", addr)

    def primitive_types(self) -> List:
        return self.client.call_method("types", "primitive_types")

    def user_types(self) -> List:
        return self.client.call_method("types", "user_types")


class RemoteArchitectureManager(ArchitectureManager):
    def __init__(self, client):
        self.client = client

    @property
    def name(self) -> str:
        return self.client.call_method("architecture", "name")

    @property
    def bits(self) -> int:
        return self.client.call_method("architecture", "bits")

    @property
    def endian(self) -> str:
        return self.client.call_method("architecture", "endian")

    def registers(self) -> list[str]:
        return self.client.call_method("architecture", "registers")

    def get_register_info(self, name: str) -> Optional[dict]:
        return self.client.call_method("architecture", "get_register_info", name)

    def calling_convention(self) -> Optional[str]:
        return self.client.call_method("architecture", "calling_convention")


class RemoteMemoryManager(MemoryManager):
    def __init__(self, client):
        self.client = client

    @property
    def base_address(self) -> int:
        return self.client.call_method("memory", "base_address")

    def read(self, addr: int, size: int) -> Optional[bytes]:
        return self.client.call_method("memory", "read", addr, size)

    def read_string(self, addr: int, max_length: int = 1024) -> Optional[str]:
        return self.client.call_method(
            "memory", "read_string", addr, max_length=max_length
        )

    def read_pointer(self, addr: int) -> Optional[int]:
        return self.client.call_method("memory", "read_pointer", addr)

    def is_valid_address(self, addr: int) -> bool:
        return self.client.call_method("memory", "is_valid_address", addr)

    def permissions(self, addr: int) -> Optional[str]:
        return self.client.call_method("memory", "permissions", addr)
