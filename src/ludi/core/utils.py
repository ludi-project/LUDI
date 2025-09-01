"""Shared utilities to eliminate redundant code patterns."""

from typing import Optional
from ..backends.base.config import (
    ConfigManager,
    get_config_manager as _get_config_manager,
)

# Cached config manager instance to avoid repeated imports
_cached_config_manager: Optional[ConfigManager] = None


def get_config_manager(config_path: Optional[str] = None) -> ConfigManager:
    """
    Cached wrapper for config manager to reduce import redundancy.

    This function provides a single point of access to the config manager
    and reduces the need for repeated imports across the codebase.
    """
    global _cached_config_manager

    # Use the original function for actual logic
    if _cached_config_manager is None or config_path:
        _cached_config_manager = _get_config_manager(config_path)

    return _cached_config_manager


def display_result(result):
    """Shared result display function to eliminate duplication."""
    if result is None:
        print("None")
    elif isinstance(result, (list, tuple)):
        if not result:
            print("[]")
        else:
            for item in result:
                display_item(item)
    else:
        display_item(result)


def display_item(item):
    """Shared item display function to eliminate duplication."""
    if hasattr(item, "name") and hasattr(item, "start"):
        print(f"{item.name or 'unnamed'} @ 0x{item.start:x}")
    elif hasattr(item, "name") and hasattr(item, "address"):
        print(f"{item.name} @ 0x{item.address:x}")
    elif hasattr(item, "from_addr") and hasattr(item, "to_addr"):
        print(f"0x{item.from_addr:x} -> 0x{item.to_addr:x} ({item.xref_type})")
    elif isinstance(item, dict):
        formatted = ", ".join(f"{k}: {v}" for k, v in item.items())
        print(f"{{{formatted}}}")
    else:
        print(item)


def discover_commands_from_function(func, fallback_commands=None):
    """
    Shared command discovery function to eliminate inspect.getsource duplication.

    Parses a function's source code to extract command patterns dynamically.
    """
    commands = []
    fallback_commands = fallback_commands or []

    import inspect

    try:
        source = inspect.getsource(func)
        lines = source.split("\n")

        for line in lines:
            line = line.strip()
            # Find command handlers - both == and startswith patterns
            if "command ==" in line and '"' in line:
                # Extract command from: elif command == "help":
                start = line.find('"') + 1
                end = line.find('"', start)
                if start > 0 and end > start:
                    cmd = line[start:end]
                    if cmd not in commands:
                        commands.append(cmd)
            elif "command.startswith(" in line and '"' in line:
                # Extract command from: elif command.startswith("load "):
                start = line.find('"') + 1
                end = line.find('"', start)
                if start > 0 and end > start:
                    cmd = line[start:end].rstrip(" ")  # Remove trailing space
                    if cmd not in commands:
                        commands.append(cmd)
            elif "command in [" in line and '"' in line:
                # Extract commands from: if command in ["exit", "quit"]:
                start_pos = line.find("[")
                end_pos = line.find("]")
                if start_pos != -1 and end_pos != -1:
                    items_str = line[start_pos + 1 : end_pos]
                    # Parse quoted items
                    import re

                    quoted_items = re.findall(r'"([^"]*)"', items_str)
                    for item in quoted_items:
                        if item not in commands:
                            commands.append(item)
    except Exception:
        # Fallback to provided commands if discovery fails
        commands = fallback_commands

    return commands
