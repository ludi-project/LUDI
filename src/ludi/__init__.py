from .core.ludi import SUPPORTED_BACKENDS

# Import core API
from .core.analyze import analyze
from .core.config import config


# Create dynamic backend functions
def _create_backend_function(backend_type):
    def backend_func(binary_path, **kwargs):
        from .core.ludi import create_backend

        return create_backend(backend_type, binary_path, **kwargs)

    backend_func.__name__ = backend_type
    backend_func.__doc__ = f"Create a {backend_type} backend instance."
    return backend_func


# Add dynamic backend functions to module
for backend_type in SUPPORTED_BACKENDS.keys():
    globals()[backend_type] = _create_backend_function(backend_type)

__all__ = ["analyze", "config"] + list(SUPPORTED_BACKENDS.keys())
