from __future__ import annotations
import shutil
from pathlib import Path
from typing import Any

from headless_ida import HeadlessIda

from ..base.decompiler import DecompilerBase
from ..base.managers import (
    ArchitectureManager,
    BinaryManager,
    FunctionManager,
    MemoryManager,
    SymbolManager,
    TypeManager,
    XRefManager,
)
from .managers import (
    IdaArchitectureManager,
    IdaBinaryManager,
    IdaFunctionManager,
    IdaMemoryManager,
    IdaSymbolManager,
    IdaTypeManager,
    IdaXRefManager,
)


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
            raise RuntimeError("IDA path not provided in configuration or kwargs.")
        if ida_path == "builtin":
            raise RuntimeError(
                f"Invalid IDA path: {ida_path}. Use a specific named backend configuration or provide explicit path. Kwargs: {kwargs}"
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

    # Configuration methods
    @staticmethod
    def get_backend_name() -> str:
        return "ida"

    @staticmethod
    def auto_discover(**kwargs) -> tuple[bool, dict[str, Any]]:
        ida_executables = ["idat64", "idat", "ida64", "ida"]

        for exe_name in ida_executables:
            if binary_path := shutil.which(exe_name):
                real_binary_path = Path(binary_path).resolve()
                for parent in [real_binary_path.parent] + list(
                    real_binary_path.parents
                ):
                    if Ida._looks_like_ida_installation(parent):
                        path = str(parent)
                        temp_config = type("Config", (), {"path": path})()
                        if Ida.validate(temp_config):
                            return True, {"path": path}
                path = str(real_binary_path.parent)
                temp_config = type("Config", (), {"path": path})()
                if Ida.validate(temp_config):
                    return True, {"path": path}

        common_paths = [
            "C:\\Program Files\\IDA Pro*",
            "C:\\Program Files (x86)\\IDA Pro*",
            "/Applications/IDA Pro*",
            "/opt/ida*",
            "/usr/local/ida*",
            "/home/*/ida*",
            "~/ida*",
        ]

        for pattern in common_paths:
            paths = Ida._glob_paths(pattern)
            for path in paths:
                if path.is_dir():
                    for exe_name in ida_executables:
                        exe_path = path / exe_name
                        if exe_path.exists():
                            temp_config = type("Config", (), {"path": str(path)})()
                            if Ida.validate(temp_config):
                                return True, {"path": str(path)}

        return False, {}

    @staticmethod
    def validate(config) -> bool:
        if config is None:
            return False

        path = (
            config.get("path")
            if isinstance(config, dict)
            else getattr(config, "path", None)
        )
        if not path:
            return False

        ida_path = Path(path)

        if ida_path.is_file():
            name = ida_path.name.lower()
            return any(ida_name in name for ida_name in ["idat", "ida64", "ida"])

        elif ida_path.is_dir():
            ida_executables = ["idat64", "idat", "ida64", "ida"]
            for exe_name in ida_executables:
                exe_path = ida_path / exe_name
                if exe_path.exists():
                    return True
            return False

        return False

    @staticmethod
    def get_default_config() -> dict:
        """Generate default configuration for IDA backend."""
        success, _ = Ida.auto_discover()
        config = {
            "type": "ida",
            "autodiscover": True,
        }

        if not success:
            config["enabled"] = False

        return config

    @staticmethod
    def _looks_like_ida_installation(path: Path) -> bool:
        if not path.is_dir():
            return False

        ida_indicators = [
            "cfg",
            "ids",
            "sig",
            "til",
            "plugins",
            "idat64",
            "idat",
            "ida64",
            "ida",
            "license.txt",
            "LICENSE",
        ]

        indicators_found = 0
        for indicator in ida_indicators:
            if (path / indicator).exists():
                indicators_found += 1

        return indicators_found >= 3

    @staticmethod
    def _glob_paths(pattern: str) -> list[Path]:
        try:
            import os

            if pattern.startswith("~"):
                pattern = os.path.expanduser(pattern)

            if "*" in pattern:
                parts = pattern.split("*")
                if len(parts) >= 2:
                    base = Path(parts[0]).parent
                    if base.exists():
                        return list(base.glob("*".join(parts[1:])))
            else:
                path = Path(pattern)
                if path.exists():
                    return [path]

            return []
        except Exception:
            return []
