from ...logger import get_logger
from ..base.config import get_config_manager
from ..base.decompiler import DecompilerBase

logger = get_logger("decompilers.auto")


class AutoDecompiler(DecompilerBase):
    def __init__(self, binary_path: str, **kwargs):
        self.binary_path = binary_path

        self._actual_backend = self._select_best_backend(binary_path, **kwargs)

    def _select_best_backend(self, binary_path: str, **kwargs) -> DecompilerBase:
        from ...ludi import LUDI

        config_manager = get_config_manager()
        available_backends = config_manager.get_available_backends()

        available_backends = [b for b in available_backends if b != "auto"]

        if not available_backends:
            raise RuntimeError("No backends available for auto selection")

        errors = []
        for backend_name in available_backends:
            try:
                # Don't pass the auto backend's path to sub-backends
                backend_kwargs = {k: v for k, v in kwargs.items() if k != "path"}
                ludi_instance = LUDI(backend_name, binary_path, **backend_kwargs)
                return ludi_instance._decompiler
            except Exception as e:
                errors.append(f"{backend_name}: {e}")
                continue

        raise RuntimeError(f"No working backend found. Tried: {'; '.join(errors)}")

    @property
    def backend_name(self) -> str:
        return f"auto->{self._actual_backend.backend_name}"

    @property
    def functions(self):
        return self._actual_backend.functions

    @property
    def symbols(self):
        return self._actual_backend.symbols

    @property
    def xrefs(self):
        return self._actual_backend.xrefs

    @property
    def binary(self):
        return self._actual_backend.binary

    def __getattr__(self, name):
        return getattr(self._actual_backend, name)
