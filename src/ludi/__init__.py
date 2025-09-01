from .ludi import LUDI, SUPPORTED_BACKENDS


# Create dynamic backend functions
def _create_backend_function(backend_name):
    def backend_func(binary_path, **kwargs):
        return LUDI(backend_name, binary_path, **kwargs)

    backend_func.__name__ = backend_name
    backend_func.__doc__ = f"Create a LUDI analyzer using the {backend_name} backend."
    return backend_func


# Add dynamic backend functions to module
for backend_name in SUPPORTED_BACKENDS.keys():
    globals()[backend_name] = _create_backend_function(backend_name)

__all__ = ["LUDI"] + list(SUPPORTED_BACKENDS.keys())
