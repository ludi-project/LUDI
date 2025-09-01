from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
import uuid
from pathlib import Path

from ..base.decompiler import DecompilerBase
from ..base.managers import BinaryManager, FunctionManager, SymbolManager, XRefManager
from .managers import (
    GhidraBinaryManager,
    GhidraFunctionManager,
    GhidraSymbolManager,
    GhidraXRefManager,
)


class GhidraNative:
    def __init__(self, binary_path: str, ghidra_path: str, project_location: str, **kwargs):
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
            binary_path, ghidra_path, project_location, headless_path=str(headless_path), **kwargs
        )

        self._function_manager = GhidraFunctionManager(self.native, self)
        self._xref_manager = GhidraXRefManager(self.native, self)
        self._symbol_manager = GhidraSymbolManager(self.native, self)
        self._binary_manager = GhidraBinaryManager(self.native, self)

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
    def backend_name(self) -> str:
        return "ghidra"

    def __del__(self):
        if hasattr(self, "native"):
            self.native.cleanup()
