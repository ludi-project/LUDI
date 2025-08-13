"""angr decompiler implementation."""

from .decompiler import Angr
from . import config  # Import config to register the provider

__all__ = ['Angr']