from typing import Optional
from .decompilers.base import DecompilerBase, FunctionManager, XRefManager, SymbolManager, BinaryManager, get_config_manager
from .decompilers.ida import Ida

# Import other decompilers if available
SUPPORTED_BACKENDS = {"ida": Ida}

try:
    from .decompilers.ghidra import Ghidra
    SUPPORTED_BACKENDS["ghidra"] = Ghidra
except ImportError:
    pass

try:
    from .decompilers.angr import Angr
    SUPPORTED_BACKENDS["angr"] = Angr
except ImportError:
    pass


class LUDI:
    """Clean unified interface for decompilers."""
    
    SUPPORTED_BACKENDS = SUPPORTED_BACKENDS
    
    def __init__(self, backend: str, binary_path: str, **kwargs):
        self.backend_name = backend.lower()
        self.binary_path = binary_path
        
        if self.backend_name not in self.SUPPORTED_BACKENDS:
            raise ValueError(f"Unsupported backend '{backend}'. Available: {list(self.SUPPORTED_BACKENDS.keys())}")
        
        backend_class = self.SUPPORTED_BACKENDS[self.backend_name]
        self._decompiler = backend_class(binary_path, **kwargs)
    
    @property
    def functions(self) -> FunctionManager:
        """Access functions."""
        return self._decompiler.functions
    
    @property
    def xrefs(self) -> XRefManager:
        """Access cross-references."""
        return self._decompiler.xrefs
    
    @property
    def symbols(self) -> SymbolManager:
        """Access symbols."""
        return self._decompiler.symbols
    
    @property
    def binary(self) -> BinaryManager:
        """Access binary info."""
        return self._decompiler.binary
    
    @classmethod
    def create(cls, backend: Optional[str] = None, binary_path: str = "", **kwargs) -> "LUDI":
        """Auto-detect backend if not specified."""
        if backend is None:
            config_manager = get_config_manager()
            available = config_manager.get_available_backends()
            if not available:
                raise RuntimeError("No decompiler backend found.")
            backend = available[0]
        return cls(backend, binary_path, **kwargs)


def ida(binary_path: str, **kwargs) -> Ida:
    """Direct IDA access."""
    return Ida(binary_path, **kwargs)


def ghidra(binary_path: str, **kwargs):
    """Direct Ghidra access."""
    try:
        return SUPPORTED_BACKENDS["ghidra"](binary_path, **kwargs)
    except KeyError:
        raise RuntimeError("Ghidra backend not available. Check LUDI_GHIDRA_PATH environment variable.")


def angr(binary_path: str, **kwargs):
    """Direct angr access."""
    try:
        return SUPPORTED_BACKENDS["angr"](binary_path, **kwargs)  
    except KeyError:
        raise RuntimeError("angr backend not available. Install with: pip install angr")


def auto(binary_path: str, preferred_backend: Optional[str] = None, **kwargs) -> LUDI:
    """Auto-detect backend with optional preference."""
    if preferred_backend and preferred_backend.lower() in SUPPORTED_BACKENDS:
        try:
            return LUDI(preferred_backend, binary_path, **kwargs)
        except Exception:
            # Fall back to auto-detection if preferred backend fails
            pass
    
    # Try backends in order of preference: IDA > Ghidra > angr
    for backend_name in ["ida", "ghidra", "angr"]:
        if backend_name in SUPPORTED_BACKENDS:
            try:
                return LUDI(backend_name, binary_path, **kwargs)
            except Exception:
                continue
    
    raise RuntimeError("No working decompiler backend found. Install IDA, Ghidra, or angr.")