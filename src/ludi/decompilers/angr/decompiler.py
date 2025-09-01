from __future__ import annotations

from ..base.config import get_config_manager
from ..base.decompiler import DecompilerBase
from ..base.managers import ArchitectureManager, BinaryManager, FunctionManager, MemoryManager, SymbolManager, TypeManager, XRefManager
from .managers import AngrArchitectureManager, AngrBinaryManager, AngrFunctionManager, AngrMemoryManager, AngrSymbolManager, AngrTypeManager, AngrXRefManager


class AngrNative:
    def __init__(self, binary_path: str, **kwargs):
        self.binary_path = binary_path

        # Remove path from kwargs if present (angr doesn't use external path)
        kwargs.pop("path", None)

        config_manager = get_config_manager()
        backend_config = config_manager.get_backend_config("angr")

        from .config import AngrConfigProvider

        provider = AngrConfigProvider()
        default_config = provider.get_default_config()

        if backend_config and backend_config.options:
            default_config.update(backend_config.options)

        self.config = type("AngrConfig", (), default_config)()

        try:
            import angr

            self.angr_module = angr
        except ImportError as e:
            raise RuntimeError("angr is not installed. Install with: pip install angr") from e

        self.project = self._create_project(**kwargs)

    def _create_project(self, **kwargs):
        project_kwargs = {
            "auto_load_libs": getattr(self.config, "auto_load_libs", False),
            "use_sim_procedures": getattr(self.config, "use_sim_procedures", True),
            "load_debug_info": getattr(self.config, "load_debug_info", False),
        }

        project_kwargs.update(kwargs)

        try:
            return self.angr_module.Project(self.binary_path, **project_kwargs)
        except Exception as e:
            raise RuntimeError(f"Failed to create angr project: {e}") from e

    def __getattr__(self, name):
        return getattr(self.project, name)


class Angr(DecompilerBase):
    def __init__(self, binary_path: str, **kwargs):
        super().__init__(binary_path, **kwargs)

        self.native = AngrNative(binary_path, **kwargs)

        self._function_manager = AngrFunctionManager(self.native, self)
        self._xref_manager = AngrXRefManager(self.native, self)
        self._symbol_manager = AngrSymbolManager(self.native, self)
        self._binary_manager = AngrBinaryManager(self.native, self)
        self._type_manager = AngrTypeManager(self.native, self)
        self._architecture_manager = AngrArchitectureManager(self.native, self)
        self._memory_manager = AngrMemoryManager(self.native, self)

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
        return "angr"
