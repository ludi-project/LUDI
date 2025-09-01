"""LUDI Core API - Package functionality that CLI mirrors."""
import importlib
import inspect
import pkgutil
from typing import Any, Callable


def discover_commands() -> dict[str, Any]:
    """Discover all available core functions by scanning core modules."""
    commands = {}

    # Get all modules in this package
    package_path = __path__
    for finder, name, ispkg in pkgutil.iter_modules(package_path):
        try:
            module = importlib.import_module(f".{name}", __name__)

            # Get all callable functions (core API functions)
            # First look for functions matching module name
            if hasattr(module, name) and inspect.isfunction(getattr(module, name)):
                commands[name] = module
                continue

            # Then look for any functions
            found_function = False
            for attr_name in dir(module):
                if attr_name.startswith("_"):
                    continue

                attr = getattr(module, attr_name)

                if inspect.isfunction(attr) and attr.__module__ == module.__name__:
                    # Top-level function defined in this module
                    commands[name] = module
                    found_function = True
                    break

            if found_function:
                continue

            # Finally look for command groups (classes with methods)
            for attr_name in dir(module):
                if attr_name.startswith("_"):
                    continue

                attr = getattr(module, attr_name)

                if (
                    inspect.isclass(attr)
                    and hasattr(attr, "__dict__")
                    and attr.__module__ == module.__name__
                ):
                    # Command group class defined in this module
                    group_commands = {}
                    for method_name in dir(attr):
                        if method_name.startswith("_"):
                            continue
                        method = getattr(attr, method_name)
                        if inspect.isfunction(method) or inspect.ismethod(method):
                            group_commands[method_name] = method

                    if group_commands:
                        commands[name] = attr
                        break

        except ImportError:
            continue

    return commands


def get_command_info(func: Callable) -> dict[str, Any]:
    """Extract command info from function for CLI generation."""
    sig = inspect.signature(func)
    doc = inspect.getdoc(func) or f"{func.__name__} command"

    return {"signature": sig, "docstring": doc, "parameters": sig.parameters}
