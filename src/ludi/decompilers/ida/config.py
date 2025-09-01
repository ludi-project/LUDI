import shutil
from pathlib import Path
from typing import Optional

from ..base.config import ConfigProvider


class IdaConfigProvider(ConfigProvider):
    @property
    def backend_name(self) -> str:
        return "ida"

    def auto_discover(self) -> Optional[str]:
        ida_executables = ["idat64", "idat", "ida64", "ida"]

        for exe_name in ida_executables:
            if binary_path := shutil.which(exe_name):
                if self.validate(binary_path):
                    real_binary_path = Path(binary_path).resolve()
                    for parent in [real_binary_path.parent] + list(real_binary_path.parents):
                        if self._looks_like_ida_installation(parent):
                            return str(parent)
                    return str(real_binary_path.parent)

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
            paths = self._glob_paths(pattern)
            for path in paths:
                if path.is_dir():
                    for exe_name in ida_executables:
                        exe_path = path / exe_name
                        if exe_path.exists() and self.validate(str(exe_path)):
                            return str(path)

        return None

    def validate(self, path: Optional[str] = None) -> bool:
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

    def _looks_like_ida_installation(self, path: Path) -> bool:
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

    def _glob_paths(self, pattern: str) -> list[Path]:
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

    def run_script(self, script_path: str, binary_path: str = None, script_args: list = None):
        from ..base.config import get_config_manager

        config_manager = get_config_manager()
        config = config_manager.get_config("ida")
        if not config or not config.path:
            raise ValueError(
                "IDA path not configured. Run 'ludi config discover' or configure manually"
            )

        ida_executable = None
        ida_dir = Path(config.path)
        for ida_exe in ["idat64", "idat", "ida64", "ida"]:
            exe_path = ida_dir / ida_exe
            if exe_path.exists():
                ida_executable = str(exe_path)
                break

        if not ida_executable:
            raise ValueError(f"No IDA executable found in {config.path}")

        cmd = [ida_executable, "-A", "-S" + script_path]

        if binary_path:
            cmd.append(binary_path)

        import os
        import subprocess
        import sys

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
