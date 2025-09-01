"""Analyze command - Binary analysis functionality."""
import os
from typing import Optional, Any
from ..backends.base.decompiler import DecompilerBase


def analyze(
    binary_path: str,
    backend: Optional[str] = None,
    backend_options: Optional[dict[str, dict[str, Any]]] = None,
    config_path: Optional[str] = None,
    **kwargs,
) -> DecompilerBase:
    """Analyze a binary file.

    Args:
        binary_path: Path to the binary file to analyze
        backend: Backend configuration to use (default: auto-detect)
        backend_options: Backend-specific options
        config_path: Path to config file
        **kwargs: Additional options passed to backend

    Returns:
        Backend instance (e.g., IDADecompiler, AngrDecompiler)
    """
    if not os.path.exists(binary_path):
        raise FileNotFoundError(f"Binary '{binary_path}' not found")

    # Create the backend instance
    from .ludi import create_backend

    return create_backend(
        backend or "auto", binary_path, backend_options, config_path, **kwargs
    )
