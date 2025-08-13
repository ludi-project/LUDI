"""Ghidra decompiler implementation."""

from __future__ import annotations

import os
import subprocess
import tempfile
import uuid
import shutil
from typing import Optional

from ..base import DecompilerBase, FunctionManager, XRefManager, SymbolManager, BinaryManager
from .config import get_ghidra_config
from .managers import GhidraFunctionManager, GhidraXRefManager, GhidraSymbolManager, GhidraBinaryManager


class GhidraNative:
    """Native Ghidra interface using headless analysis."""
    
    def __init__(self, binary_path: str, ghidra_path: str, project_location: str, **kwargs):
        self.binary_path = binary_path
        self.ghidra_path = ghidra_path
        self.project_location = project_location
        self.project_name = f"ludi_project_{uuid.uuid4().hex[:8]}"
        self.headless_path = kwargs.get('headless_path')
        
        # Ensure project directory exists
        os.makedirs(self.project_location, exist_ok=True)
        
        # Initialize project
        self._init_project()
    
    def _init_project(self):
        """Initialize Ghidra project and import binary."""
        if not self.headless_path:
            raise RuntimeError("Ghidra headless script not found")
        
        # Import binary into project
        cmd = [
            self.headless_path,
            self.project_location,
            self.project_name,
            "-import", self.binary_path,
            "-overwrite",
            "-analysisTimeoutPerFile", "300"  # 5 minute timeout
        ]
        
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=600,  # 10 minute timeout for import
                check=False
            )
            
            if result.returncode != 0:
                # Try to extract useful error info
                error_msg = result.stderr if result.stderr else "Unknown error"
                raise RuntimeError(f"Failed to initialize Ghidra project: {error_msg}")
                
        except subprocess.TimeoutExpired:
            raise RuntimeError("Ghidra project initialization timed out")
    
    def _run_script(self, script_content: str, script_name: str) -> Optional[str]:
        """Run a Ghidra script and return output."""
        # Create temporary script file
        with tempfile.NamedTemporaryFile(mode='w', suffix='.java', delete=False) as f:
            f.write(script_content)
            script_path = f.name
        
        try:
            # Run script with headless Ghidra
            cmd = [
                self.headless_path,
                self.project_location,
                self.project_name,
                "-process", os.path.basename(self.binary_path),
                "-scriptPath", os.path.dirname(script_path),
                "-postScript", os.path.basename(script_path),
                "-analysisTimeoutPerFile", "60"
            ]
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=120,  # 2 minute timeout for scripts
                check=False
            )
            
            # Extract script output from Ghidra's verbose output
            if result.stdout:
                # Look for our script output in stdout
                lines = result.stdout.split('\n')
                output_lines = []
                in_script_output = False
                
                for line in lines:
                    # Simple heuristic to detect script output
                    if any(marker in line for marker in ['INFO', 'SCRIPT']):
                        continue
                    if line.strip() and not line.startswith('WARN') and not line.startswith('ERROR'):
                        output_lines.append(line)
                
                return '\n'.join(output_lines) if output_lines else None
            
            return None
            
        except subprocess.TimeoutExpired:
            return None
        finally:
            # Clean up temporary script file
            try:
                os.unlink(script_path)
            except OSError:
                pass
    
    def cleanup(self):
        """Clean up Ghidra project."""
        project_dir = os.path.join(self.project_location, self.project_name + ".rep")
        if os.path.exists(project_dir):
            try:
                shutil.rmtree(project_dir)
            except OSError:
                pass


class Ghidra(DecompilerBase):
    """Ghidra decompiler implementation."""
    
    def __init__(self, binary_path: str, **kwargs):
        super().__init__(binary_path, **kwargs)
        
        # Get Ghidra configuration
        ghidra_config = get_ghidra_config()
        if not ghidra_config.path:
            raise RuntimeError("Ghidra path not configured. Set LUDI_GHIDRA_PATH environment variable.")
        
        if not ghidra_config.headless_path:
            raise RuntimeError("Ghidra headless script not found. Check LUDI_GHIDRA_PATH.")
        
        self.native = GhidraNative(
            binary_path,
            ghidra_config.path,
            ghidra_config.project_location,
            headless_path=ghidra_config.headless_path,
            **kwargs
        )
        
        # Initialize managers
        self._function_manager = GhidraFunctionManager(self.native, self)
        self._xref_manager = GhidraXRefManager(self.native, self)
        self._symbol_manager = GhidraSymbolManager(self.native, self)
        self._binary_manager = GhidraBinaryManager(self.native, self)
    
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
    
    def __del__(self):
        """Clean up Ghidra project on destruction."""
        if hasattr(self, 'native'):
            self.native.cleanup()