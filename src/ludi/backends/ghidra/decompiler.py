from __future__ import annotations

import importlib.util
import os
import shutil
import subprocess
import tempfile
import uuid
from pathlib import Path
from typing import Any

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
    GhidraArchitectureManager,
    GhidraBinaryManager,
    GhidraFunctionManager,
    GhidraMemoryManager,
    GhidraSymbolManager,
    GhidraTypeManager,
    GhidraXRefManager,
)


class GhidraNative:
    def __init__(
        self, binary_path: str, ghidra_path: str, project_location: str, **kwargs
    ):
        self.binary_path = binary_path
        self.ghidra_path = ghidra_path
        self.project_location = project_location
        self.project_name = f"ludi_project_{uuid.uuid4().hex[:8]}"
        self.headless_path = kwargs.get("headless_path")

        os.makedirs(self.project_location, exist_ok=True)

        self._init_project()

    def _init_project(self):
        if not self.headless_path:
            raise RuntimeError("Ghidra headless script not found")

        cmd = [
            self.headless_path,
            self.project_location,
            self.project_name,
            "-import",
            self.binary_path,
            "-overwrite",
            "-analysisTimeoutPerFile",
            "300",  # 5 minute timeout
        ]

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=600,  # 10 minute timeout for import
                check=False,
            )

            if result.returncode != 0:
                error_msg = result.stderr if result.stderr else "Unknown error"
                raise RuntimeError(f"Failed to initialize Ghidra project: {error_msg}")

        except subprocess.TimeoutExpired as e:
            raise RuntimeError("Ghidra project initialization timed out") from e

    def _run_script(self, script_content: str, script_name: str) -> str | None:
        with tempfile.NamedTemporaryFile(mode="w", suffix=".java", delete=False) as f:
            f.write(script_content)
            script_path = f.name

        try:
            cmd = [
                self.headless_path,
                self.project_location,
                self.project_name,
                "-process",
                os.path.basename(self.binary_path),
                "-scriptPath",
                os.path.dirname(script_path),
                "-postScript",
                os.path.basename(script_path),
                "-analysisTimeoutPerFile",
                "60",
            ]

            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=120,  # 2 minute timeout for scripts
                check=False,
            )

            if result.stdout:
                lines = result.stdout.split("\n")
                output_lines = []

                for line in lines:
                    if any(marker in line for marker in ["INFO", "SCRIPT"]):
                        continue
                    if (
                        line.strip()
                        and not line.startswith("WARN")
                        and not line.startswith("ERROR")
                    ):
                        output_lines.append(line)

                return "\n".join(output_lines) if output_lines else None

            return None

        except subprocess.TimeoutExpired:
            return None
        finally:
            try:
                os.unlink(script_path)
            except OSError:
                pass

    def cleanup(self):
        project_dir = os.path.join(self.project_location, self.project_name + ".rep")
        if os.path.exists(project_dir):
            try:
                shutil.rmtree(project_dir)
            except OSError:
                pass


class Ghidra(DecompilerBase):
    def __init__(self, binary_path: str, **kwargs):
        super().__init__(binary_path, **kwargs)

        ghidra_path = kwargs.get("path")
        if not ghidra_path:
            raise RuntimeError(
                "Ghidra path not provided. Use LUDI class for proper initialization."
            )

        headless_path = Path(ghidra_path) / "support" / "analyzeHeadless"
        if not headless_path.exists():
            headless_path = Path(ghidra_path) / "support" / "analyzeHeadless.bat"
        if not headless_path.exists():
            raise RuntimeError(f"Ghidra headless script not found in {ghidra_path}")

        project_location = "/tmp/ludi_ghidra_projects"

        self.native = GhidraNative(
            binary_path,
            ghidra_path,
            project_location,
            headless_path=str(headless_path),
            **kwargs,
        )

        self._function_manager = GhidraFunctionManager(self.native, self)
        self._xref_manager = GhidraXRefManager(self.native, self)
        self._symbol_manager = GhidraSymbolManager(self.native, self)
        self._binary_manager = GhidraBinaryManager(self.native, self)
        self._type_manager = GhidraTypeManager(self.native, self)
        self._architecture_manager = GhidraArchitectureManager(self.native, self)
        self._memory_manager = GhidraMemoryManager(self.native, self)

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
        return "ghidra"

    # Configuration methods
    @staticmethod
    def get_backend_name() -> str:
        return "ghidra"

    @staticmethod
    def auto_discover(**kwargs) -> tuple[bool, dict[str, Any]]:
        ghidra_install_dir = os.environ.get("GHIDRA_INSTALL_DIR")
        if ghidra_install_dir and os.path.exists(ghidra_install_dir):
            temp_config = type("Config", (), {"path": ghidra_install_dir})()
            if Ghidra.validate(temp_config):
                return True, {"path": ghidra_install_dir}

        if importlib.util.find_spec("pyhidra") is not None:
            for env_var in ["GHIDRA_HOME", "GHIDRA_ROOT"]:
                ghidra_dir = os.environ.get(env_var)
                if ghidra_dir and os.path.exists(ghidra_dir):
                    temp_config = type("Config", (), {"path": ghidra_dir})()
                    if Ghidra.validate(temp_config):
                        return True, {"path": ghidra_dir}

        headless_scripts = ["analyzeHeadless", "analyzeHeadless.bat"]

        for script_name in headless_scripts:
            if script_path := shutil.which(script_name):
                script_path_obj = Path(script_path)
                for parent in script_path_obj.parents:
                    if parent.name.lower().startswith("ghidra"):
                        temp_config = type("Config", (), {"path": str(parent)})()
                        if Ghidra.validate(temp_config):
                            return True, {"path": str(parent)}

        common_paths = [
            "/opt/ghidra*",
            "/usr/local/ghidra*",
            "/home/*/ghidra*",
            "/Applications/ghidra*",
            "~/ghidra*",
            "C:\\Program Files\\ghidra*",
            "C:\\ghidra*",
        ]

        for pattern in common_paths:
            paths = Ghidra._glob_paths(pattern)
            for path in paths:
                if path.is_dir():
                    temp_config = type("Config", (), {"path": str(path)})()
                    if Ghidra.validate(temp_config):
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

        ghidra_path = Path(path)

        if ghidra_path.is_dir():
            headless_script = ghidra_path / "support" / "analyzeHeadless"
            headless_bat = ghidra_path / "support" / "analyzeHeadless.bat"
            return headless_script.exists() or headless_bat.exists()

        elif ghidra_path.is_file():
            name = ghidra_path.name.lower()
            return "analyzeheadless" in name

        return False

    @staticmethod
    def get_default_config() -> dict:
        """Generate default configuration for Ghidra backend."""
        success, _ = Ghidra.auto_discover()
        config = {
            "type": "ghidra",
            "autodiscover": True,
        }

        if not success:
            config["enabled"] = False

        return config

    @staticmethod
    def _glob_paths(pattern: str) -> list[Path]:
        try:
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

    def __del__(self):
        if hasattr(self, "native"):
            self.native.cleanup()
