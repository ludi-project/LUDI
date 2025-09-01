from __future__ import annotations

from headless_ida import HeadlessIda

from ..base.decompiler import DecompilerBase
from ..base.managers import ArchitectureManager, BinaryManager, FunctionManager, MemoryManager, SymbolManager, TypeManager, XRefManager
from .managers import IdaArchitectureManager, IdaBinaryManager, IdaFunctionManager, IdaMemoryManager, IdaSymbolManager, IdaTypeManager, IdaXRefManager


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

        ida_path = kwargs.get("path")
        if not ida_path:
            raise RuntimeError("IDA path not provided. Use LUDI class for proper initialization.")
        if ida_path == "builtin":
            # Debug: print more details about why we're getting builtin
            from ..base.config import get_config_manager

            config_manager = get_config_manager()
            ida_config = config_manager.get_backend_config("ida")
            raise RuntimeError(
                f"Invalid IDA path: {ida_path}. Config path: {ida_config.path if ida_config else 'NO CONFIG'}. Kwargs: {kwargs}"
            )

        # Remove ida_path from kwargs since it's passed as positional arg
        kwargs_for_native = kwargs.copy()
        kwargs_for_native.pop("path", None)
        self.native = IdaNative(binary_path, ida_path, **kwargs_for_native)
        self._function_manager = IdaFunctionManager(self.native, self)
        self._xref_manager = IdaXRefManager(self.native, self)
        self._symbol_manager = IdaSymbolManager(self.native, self)
        self._binary_manager = IdaBinaryManager(self.native, self)
        self._type_manager = IdaTypeManager(self.native, self)
        self._architecture_manager = IdaArchitectureManager(self.native, self)
        self._memory_manager = IdaMemoryManager(self.native, self)

    @property
    def functions(self) -> FunctionManager:
        return self._function_manager

    @property
    def xrefs(self) -> XRefManager:
        return self._xref_manager

    @property
    def symbols(self) -> SymbolManager:
        return self._symbol_manager

    @property
    def binary(self) -> BinaryManager:
        return self._binary_manager

    @property
    def types(self) -> TypeManager:
        return self._type_manager

    @property
    def architecture(self) -> ArchitectureManager:
        return self._architecture_manager

    @property
    def memory(self) -> MemoryManager:
        return self._memory_manager

    @property
    def backend_name(self) -> str:
        return "ida"
