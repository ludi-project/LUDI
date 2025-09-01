from typing import List, Optional

from ..base.managers import BinaryManager, FunctionManager, SymbolManager, XRefManager
from ..base.types import Function, Symbol, XRef


class RemoteFunctionManager(FunctionManager):
    def __init__(self, client):
        self.client = client

    def get_all(self) -> List[Function]:
        return self.client.call_method("functions", "get_all")

    def get_by_address(self, address: int) -> Optional[Function]:
        return self.client.call_method("functions", "get_by_address", address)

    def get_by_name(self, name: str) -> Optional[Function]:
        return self.client.call_method("functions", "get_by_name", name)

    def get_between(self, start_addr: int, end_addr: int) -> List[Function]:
        return self.client.call_method("functions", "get_between", start_addr, end_addr)

    def get_decompiled_code(self, address: int, level: Optional[str] = None) -> Optional[str]:
        return self.client.call_method("functions", "get_decompiled_code", address, level=level)


class RemoteSymbolManager(SymbolManager):
    def __init__(self, client):
        self.client = client

    def get_all(self) -> List[Symbol]:
        return self.client.call_method("symbols", "get_all")

    def get_by_address(self, address: int) -> Optional[Symbol]:
        return self.client.call_method("symbols", "get_by_address", address)

    def get_by_name(self, name: str) -> Optional[Symbol]:
        return self.client.call_method("symbols", "get_by_name", name)


class RemoteXRefManager(XRefManager):
    def __init__(self, client):
        self.client = client

    def get_xrefs_to(self, address: int) -> List[XRef]:
        return self.client.call_method("xrefs", "get_xrefs_to", address)

    def get_xrefs_from(self, address: int) -> List[XRef]:
        return self.client.call_method("xrefs", "get_xrefs_from", address)


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
