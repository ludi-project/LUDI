from __future__ import annotations

from headless_ida import HeadlessIda

from ..base import DecompilerBase, FunctionManager, XRefManager, SymbolManager, BinaryManager
from .config import get_ida_config
from .managers import IdaFunctionManager, IdaXRefManager, IdaSymbolManager, IdaBinaryManager


class IdaNative:
    _DEFAULT_LOAD_BASE = 0x0

    def __init__(self, binary_path: str, ida_path: str, **kwargs) -> None:
        self.binary_path = binary_path
        self._headlessida = HeadlessIda(ida_path, binary_path)
        ida_libs = [
            "idc",
            "idautils",
            "idaapi",
            "ida_funcs",
            "ida_xref",
            "ida_nalt",
            "ida_auto",
            "ida_hexrays",
            "ida_name",
            "ida_expr",
            "ida_typeinf",
            "ida_loader",
            "ida_lines",
            "ida_segment",
            "ida_gdl",
            "ida_ua",
            "ida_bytes",
            "ida_entry",
            "ida_ida",
            "ida_idp",
            "ida_frame",
        ]
        for lib in ida_libs:
            setattr(self, lib, self._headlessida.import_module(lib))



class Ida(DecompilerBase):
    def __init__(self, binary_path: str, **kwargs) -> None:
        super().__init__(binary_path, **kwargs)
        
        # Get IDA path from config
        ida_config = get_ida_config()
        ida_path = ida_config.path
        if not ida_path:
            raise RuntimeError("IDA path not configured. Set LUDI_IDA_PATH environment variable or use config.")
        
        self.native = IdaNative(binary_path, ida_path, **kwargs)
        self._function_manager = IdaFunctionManager(self.native, self)
        self._xref_manager = IdaXRefManager(self.native, self)
        self._symbol_manager = IdaSymbolManager(self.native, self)
        self._binary_manager = IdaBinaryManager(self.native, self)

    @property
    def functions(self) -> FunctionManager:
        """Get the function manager for this decompiler."""
        return self._function_manager
    
    @property
    def xrefs(self) -> XRefManager:
        """Get the cross-reference manager for this decompiler."""
        return self._xref_manager
    
    @property
    def symbols(self) -> SymbolManager:
        """Get the symbol manager for this decompiler."""
        return self._symbol_manager
    
    @property
    def binary(self) -> BinaryManager:
        """Get the binary manager for this decompiler."""
        return self._binary_manager

