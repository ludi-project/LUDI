import importlib.util
from typing import Optional

from ..base.config import ConfigProvider


class AngrConfigProvider(ConfigProvider):
    @property
    def backend_name(self) -> str:
        return "angr"

    def get_default_config(self) -> dict:
        return {
            "auto_load_libs": False,  # Performance optimization
            "load_debug_info": False,  # Performance optimization
            "use_sim_procedures": True,
        }

    def auto_discover(self) -> Optional[str]:
        if importlib.util.find_spec("angr") is not None:
            return "python-package"
        return None

    def validate(self, path: Optional[str] = None) -> bool:
        return importlib.util.find_spec("angr") is not None

    def run_script(self, script_path: str, binary_path: str = None, script_args: list = None):
        import os
        import subprocess
        import sys

        cmd = [sys.executable, script_path]

        env = os.environ.copy()

        if binary_path:
            env["LUDI_BINARY_PATH"] = binary_path

        if script_args:
            cmd.extend(script_args)

        print(f"Executing: {' '.join(cmd)}")
        if binary_path:
            print(f"Binary available via environment variable: LUDI_BINARY_PATH={binary_path}")

        result = subprocess.run(cmd, env=env, capture_output=False)
        sys.exit(result.returncode)
