from importlib import metadata

# Import decompilers module to trigger auto-registration
from . import decompilers

from .decompilers.ida import Ida
from .ludi import LUDI, ida, auto

# Import other decompilers if available
try:
    from .decompilers.ghidra import Ghidra
    __all__ = ["LUDI", "Ida", "Ghidra", "ida", "auto", "__version__"]
except ImportError:
    __all__ = ["LUDI", "Ida", "ida", "auto", "__version__"]

try:
    from .decompilers.angr import Angr
    if "Angr" not in __all__:
        __all__.insert(-2, "Angr")  # Insert before "auto" and "__version__"
except ImportError:
    pass

# Import convenience functions for other decompilers
try:
    from .ludi import ghidra
    globals()["ghidra"] = ghidra
    if "ghidra" not in __all__:
        __all__.insert(-1, "ghidra")  # Insert before "__version__"
except (ImportError, NameError):
    pass

try:
    from .ludi import angr as angr_func
    globals()["angr"] = angr_func
    if "angr" not in __all__:
        __all__.insert(-1, "angr")  # Insert before "__version__"
except (ImportError, NameError):
    pass


__version__ = metadata.version("ludi")
