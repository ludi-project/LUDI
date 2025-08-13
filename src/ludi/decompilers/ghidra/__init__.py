"""Ghidra decompiler implementation."""

from .decompiler import Ghidra
from . import config  # Import config to register the provider

__all__ = ['Ghidra']