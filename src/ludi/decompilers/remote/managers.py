from typing import List, Optional

from ..base.managers import BinaryManager, FunctionManager, SymbolManager, XRefManager
from ..base.types import Function, Symbol, XRef


class RemoteFunctionManager(FunctionManager):
    def __init__(self, client):
        self.client = client

    def all(self) -> List[Function]:
        return self.client.call_method("functions", "all")

    def by_address(self, address: int) -> Optional[Function]:
        return self.client.call_method("functions", "by_address", address)

    def by_name(self, name: str) -> Optional[Function]:
        return self.client.call_method("functions", "by_name", name)

    def get_between(self, start_addr: int, end_addr: int) -> List[Function]:
        return self.client.call_method("functions", "get_between", start_addr, end_addr)

    def decompiled_code(self, address: int, level: Optional[str] = None) -> Optional[str]:
        return self.client.call_method("functions", "decompiled_code", address, level=level)

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

    def all(self) -> List[Symbol]:
        return self.client.call_method("symbols", "all")

    def by_address(self, address: int) -> Optional[Symbol]:
        return self.client.call_method("symbols", "by_address", address)

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

    def get_xrefs_to(self, address: int) -> List[XRef]:
        return self.client.call_method("xrefs", "get_xrefs_to", address)

    def get_xrefs_from(self, address: int) -> List[XRef]:
        return self.client.call_method("xrefs", "get_xrefs_from", address)

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

    def get_segments(self) -> List[dict]:
        return self.client.call_method("binary", "get_segments")

    def get_sections(self) -> List[dict]:
        return self.client.call_method("binary", "get_sections")

    def get_entry_points(self) -> List[int]:
        return self.client.call_method("binary", "get_entry_points")

    def get_architecture(self) -> str:
        return self.client.call_method("binary", "get_architecture")

    def get_base_address(self) -> int:
        return self.client.call_method("binary", "get_base_address")
