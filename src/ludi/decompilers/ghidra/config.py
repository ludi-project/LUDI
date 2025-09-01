import importlib.util
import os
import shutil
from pathlib import Path
from typing import Optional

from ..base.config import ConfigProvider


class GhidraConfigProvider(ConfigProvider):
    @property
    def backend_name(self) -> str:
        return "ghidra"

    def auto_discover(self) -> Optional[str]:
        ghidra_install_dir = os.environ.get("GHIDRA_INSTALL_DIR")
        if ghidra_install_dir and os.path.exists(ghidra_install_dir):
            if self.validate(ghidra_install_dir):
                return ghidra_install_dir

        if importlib.util.find_spec("pyhidra") is not None:
            for env_var in ["GHIDRA_HOME", "GHIDRA_ROOT"]:
                ghidra_dir = os.environ.get(env_var)
                if ghidra_dir and os.path.exists(ghidra_dir):
                    if self.validate(ghidra_dir):
                        return ghidra_dir

        headless_scripts = ["analyzeHeadless", "analyzeHeadless.bat"]

        for script_name in headless_scripts:
            if script_path := shutil.which(script_name):
                script_path_obj = Path(script_path)
                for parent in script_path_obj.parents:
                    if parent.name.lower().startswith("ghidra") and self.validate(str(parent)):
                        return str(parent)

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
            paths = self._glob_paths(pattern)
            for path in paths:
                if path.is_dir() and self.validate(str(path)):
                    return str(path)

        return None

    def validate(self, path: Optional[str] = None) -> bool:
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

    def _glob_paths(self, pattern: str) -> list[Path]:
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

    def run_script(self, script_path: str, binary_path: str = None, script_args: list = None):
        from ..base.config import get_config_manager

        config_manager = get_config_manager()
        config = config_manager.get_config("ghidra")
        if not config or not config.path:
            raise ValueError(
                "Ghidra path not configured. Run 'ludi config discover' or configure manually"
            )

        import os
        import subprocess
        import sys
        import tempfile

        with tempfile.TemporaryDirectory() as temp_dir:
            project_dir = os.path.join(temp_dir, "ghidra_project")

            headless_path = Path(config.path) / "support" / "analyzeHeadless"
            if not headless_path.exists():
                headless_path = Path(config.path) / "support" / "analyzeHeadless.bat"

            if not headless_path.exists():
                raise ValueError(f"analyzeHeadless script not found in {config.path}")

            cmd = [str(headless_path), project_dir, "temp_project"]

            if binary_path:
                cmd.extend(["-import", binary_path])

            cmd.extend(["-postScript", script_path])

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
