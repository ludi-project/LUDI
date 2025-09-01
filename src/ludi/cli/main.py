import argparse
import os
import sys
from pathlib import Path

# Import removed to avoid circular import - will import when needed
from ..assets import get_banner, get_title
from ..logger import get_logger, setup_logging
from .config import ConfigCLI

logger = get_logger("cli.main")

try:
    import readline

    READLINE_AVAILABLE = True
except ImportError:
    READLINE_AVAILABLE = False


def _display_ascii_art():
    print(get_banner())


def _expand_shorthand(args, parser):
    """Expand shorthand commands if unambiguous."""
    if not args or args[0].startswith("-"):
        return args

    command = args[0]

    # Get all available commands from subparsers
    choices = []
    for action in parser._actions:
        if hasattr(action, "choices") and action.choices:
            choices = list(action.choices.keys())
            break

    if not choices:
        return args

    # Find exact match first
    if command in choices:
        return args

    # Find prefix matches
    matches = [cmd for cmd in choices if cmd.startswith(command)]

    if len(matches) == 1:
        # Unambiguous shorthand - expand it
        new_args = [matches[0]] + args[1:]
        logger.debug(f"Expanded '{command}' to '{matches[0]}'")
        return new_args
    elif len(matches) > 1:
        # Ambiguous shorthand - let argparse handle the error
        return args
    else:
        # No matches - let argparse handle the error
        return args


def _setup_command_parser(parser):
    """Setup parser by discovering commands from ludi.core."""
    from ..core import discover_commands
    from ..core.utils import get_config_manager

    config_manager = get_config_manager()
    available_backends = list(config_manager.load_config().keys())

    parser.add_argument(
        "-v", "--verbose", action="store_true", help="Enable verbose output"
    )
    parser.add_argument("--debug", action="store_true", help="Enable debug logging")
    parser.add_argument(
        "--config", help="Path to config file (default: ~/.config/ludi/config.yaml)"
    )

    # Discover and add commands dynamically
    subparsers = parser.add_subparsers(dest="command", help="Available commands")
    commands = discover_commands()

    for command_name, command_module_or_class in commands.items():
        if command_name == "analyze":
            _add_analyze_command(
                subparsers, command_module_or_class, available_backends
            )
        elif command_name == "config":
            _add_config_command(subparsers, command_module_or_class, parser)
        else:
            # Generic command handler for future commands
            _add_generic_command(subparsers, command_name, command_module_or_class)

    # Add remaining non-dynamic commands (these could be moved to commands/ later)
    _add_remaining_commands(subparsers, parser)


def _add_analyze_command(subparsers, analyze_module, available_backends):
    """Add analyze command based on discovered module."""
    import inspect

    analyze_func = getattr(analyze_module, "analyze")
    doc = inspect.getdoc(analyze_func) or "Analyze a binary file"

    analyze_parser = subparsers.add_parser("analyze", help=doc.split("\n")[0])

    # Add binary argument first
    analyze_parser.add_argument("binary", help="Binary file to analyze")
    analyze_parser.add_argument(
        "--backend",
        choices=available_backends,
        help="Backend to use (default: auto-detect)",
    )

    # Add subcommands for analyze (optional - show help when no action specified)
    analyze_subparsers = analyze_parser.add_subparsers(
        dest="analyze_action", help="Analysis actions", required=False
    )

    # Add shell subcommand
    analyze_subparsers.add_parser(
        "shell", help="Start interactive shell for binary analysis"
    )

    # Add manager subcommands
    from ..cli.analyze import AnalyzeCLI

    analyze_cli = AnalyzeCLI()

    for manager_name, manager_class in analyze_cli.manager_classes.items():
        # Filter out non-manager classes like 'backend_name' which is just str
        if (
            manager_class
            and manager_name not in ["backend_name"]
            and manager_class != str
        ):
            manager_parser = analyze_subparsers.add_parser(
                manager_name, help=f"Access {manager_name} manager methods"
            )
            manager_sub = manager_parser.add_subparsers(
                dest=f"{manager_name}_action",
                help=f"{manager_name} methods",
                required=False,
            )
            analyze_cli._add_method_parsers(manager_sub, manager_name, manager_class)


def _add_config_command(subparsers, config_class, parser):
    """Add config command group based on discovered class."""
    import inspect

    config_parser = subparsers.add_parser("config", help="Configuration management")
    parser._config_parser = config_parser  # Store reference
    config_subparsers = config_parser.add_subparsers(dest="config_command")

    # Inspect config class methods
    config_instance = config_class()
    for method_name in dir(config_instance):
        if method_name.startswith("_"):
            continue

        method = getattr(config_instance, method_name)
        if not callable(method):
            continue

        sig = inspect.signature(method)
        doc = inspect.getdoc(method) or f"{method_name} command"

        method_parser = config_subparsers.add_parser(
            method_name, help=doc.split("\n")[0]
        )

        # Add arguments based on method signature
        for param_name, param in sig.parameters.items():
            if param_name == "self":
                continue

            if param.annotation == bool:
                method_parser.add_argument(
                    f"--{param_name.replace('_', '-')}",
                    action="store_true",
                    help=f"{param_name} flag",
                )
            elif param.default is not inspect.Parameter.empty:
                method_parser.add_argument(
                    f"--{param_name.replace('_', '-')}"
                    if param.default is not None
                    else param_name,
                    default=param.default,
                    help=f"{param_name} parameter",
                )
            else:
                method_parser.add_argument(param_name, help=f"{param_name} parameter")


def _add_generic_command(subparsers, command_name, command_module):
    """Add a generic command based on discovered module."""
    # For future extensibility
    pass


def _add_remaining_commands(subparsers, parser):
    """Add commands that haven't been moved to ludi.commands yet."""
    # Shell command
    subparsers.add_parser("shell", help="Interactive LUDI shell")

    # Server command
    server_parser = subparsers.add_parser("server", help="Run LUDI server")
    server_parser.add_argument("--host", default="localhost", help="Host to bind to")
    server_parser.add_argument("--port", type=int, default=8080, help="Port to bind to")

    # Completion command
    completion_parser = subparsers.add_parser(
        "completion", help="Generate completion scripts"
    )
    completion_parser.add_argument(
        "shell", choices=["bash", "zsh", "fish"], help="Shell type"
    )

    # Native command
    native_parser = subparsers.add_parser("native", help="Run native backend scripts")
    parser._native_parser = native_parser  # Store reference for later use
    native_subparsers = native_parser.add_subparsers(dest="native_action")
    run_parser = native_subparsers.add_parser("run", help="Run a native script")
    run_parser.add_argument("script", help="Script to run")
    run_parser.add_argument("args", nargs="*", help="Script arguments")


def _resolve_backend_and_binary(args):
    backend = None
    binary = None

    if hasattr(args, "backend") and args.backend:
        backend = args.backend
    if hasattr(args, "binary") and args.binary:
        binary = args.binary

    if not backend:
        backend = os.environ.get("LUDI_BACKEND")
    if not binary:
        binary = os.environ.get("LUDI_BINARY")

    if not backend:
        try:
            from .config import ConfigCLI

            ConfigCLI()
        except ImportError:
            pass

    if not backend:
        try:
            from ..core.utils import get_config_manager

            config_manager = get_config_manager()
            backends = config_manager.get_backends()

            for backend_wrapper in backends:
                discovered = backend_wrapper.auto_discover()
                if discovered and "path" in discovered:
                    backend = backend_wrapper.backend_name
                    break
        except (ImportError, AttributeError):
            from ..core.utils import get_config_manager

            config_manager = get_config_manager()
            available = config_manager.get_available_backend_configs()
            backend = available[0] if available else None
            if not backend:
                logger.error("No backends available. Run 'ludi config discover' first.")
                print(
                    "Error: No backends available. Run 'ludi config discover' first.",
                    file=sys.stderr,
                )
                sys.exit(1)

    return backend, binary


def _run_native_script(
    backend: str, script_path: str, binary_path: str = None, script_args: list = None
):
    script_args = script_args or []

    if not os.path.exists(script_path):
        logger.error(f"Script file not found: {script_path}")
        print(f"Error: Script file '{script_path}' not found", file=sys.stderr)
        sys.exit(1)

    if binary_path and not os.path.exists(binary_path):
        logger.error(f"Binary file not found: {binary_path}")
        print(f"Error: Binary file '{binary_path}' not found", file=sys.stderr)
        sys.exit(1)

    script_path = os.path.abspath(script_path)
    if binary_path:
        binary_path = os.path.abspath(binary_path)

    print(f"Running native {backend} script: {script_path}")
    if binary_path:
        print(f"Target binary: {binary_path}")
    if script_args:
        print(f"Script arguments: {' '.join(script_args)}")
    print()

    try:
        from ..core.utils import get_config_manager

        config_manager = get_config_manager()

        if backend in config_manager._backends:
            backend_wrapper = config_manager._backends[backend]
            backend_wrapper.run_script(script_path, binary_path, script_args)
        else:
            print(
                f"Error: Script execution not supported for backend '{backend}'",
                file=sys.stderr,
            )
            sys.exit(1)
    except Exception as e:
        print(f"Error running {backend} script: {e}", file=sys.stderr)
        sys.exit(1)


def main():
    temp_parser = argparse.ArgumentParser(add_help=False)
    temp_parser.add_argument("--debug", action="store_true")
    temp_parser.add_argument("-v", "--verbose", action="store_true")
    temp_parser.add_argument("--config")
    temp_args, _ = temp_parser.parse_known_args()

    if temp_args.debug:
        setup_logging(level="DEBUG", verbose=True)
    elif temp_args.verbose:
        setup_logging(level="INFO", verbose=True)
    else:
        setup_logging()

    if len(sys.argv) > 1 and sys.argv[1] == "__complete":
        __complete_command()
        return

    # Standard command mode with subcommands
    parser = argparse.ArgumentParser(
        prog="ludi",
        description=get_title(),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    _setup_command_parser(parser)

    # Manager-specific commands are handled within the binary shell, not as top-level commands

    # Apply shorthand expansion to arguments
    expanded_args = _expand_shorthand(sys.argv[1:], parser)
    args = parser.parse_args(expanded_args)

    # Set config path environment variable if provided
    if hasattr(args, "config") and args.config:
        os.environ["LUDI_CONFIG_PATH"] = args.config

    # Handle missing command
    if not args.command:
        _display_ascii_art()
        print()
        parser.print_help()
        return

    config_cli = ConfigCLI()

    if args.command == "analyze":
        _handle_analyze_command_dynamic(args)

    elif args.command == "config":
        _handle_config_command_dynamic(args)

    elif args.command == "config_old":
        if not args.config_command:
            parser._config_parser.print_help()
            return

        try:
            if args.config_command == "show":
                config_cli.show_config(validate=args.validate)
            elif args.config_command == "discover":
                config_cli.discover_tools(save=args.save)
            elif args.config_command == "set":
                config_cli.set_config(
                    backend=args.backend,
                    path=args.path,
                    enabled=args.enabled,
                    default=args.default,
                )
            elif args.config_command == "test":
                config_cli.test_installations(backend=args.backend)
            elif args.config_command == "reset":
                config_cli.reset_config(confirm=args.confirm)
        except Exception as e:
            print(f"Error: {e}", file=sys.stderr)
            sys.exit(1)

    elif args.command == "shell":
        _start_interactive_shell()

    elif args.command == "server":
        _start_server(args.host, args.port)

    elif args.command == "native":
        if not args.native_action:
            parser._native_parser.print_help()
            return
        elif args.native_action == "run":
            backend, binary = _resolve_backend_and_binary(args)
            target_binary = binary or getattr(args, "binary", None)
            _run_native_script(backend, args.script, target_binary, args.args or [])

    elif args.command == "completion":
        _generate_completion(args.shell_type)


def _handle_analyze_command_dynamic(args):
    """Handle analyze command using the package API."""
    import ludi

    try:
        # Use the package API directly
        backend = ludi.analyze(args.binary, backend=getattr(args, "backend", None))

        print(f"Loaded binary: {args.binary}")
        print(f"Using backend: {backend.backend_name}")

        action = getattr(args, "analyze_action", None)

        if action == "shell":
            # Start interactive shell
            _start_binary_shell(backend, args.binary)
        elif action and action != "shell":
            # Handle manager commands non-interactively (dynamically discover managers)
            from ..cli.analyze import AnalyzeCLI

            analyze_cli = AnalyzeCLI()

            # Check if this is a valid manager
            if action in analyze_cli.manager_classes and action != "backend_name":
                analyze_cli.backend = backend  # Set the backend

                # Check if a specific method was requested
                method_action = getattr(args, f"{action}_action", None)
                if method_action:
                    # Execute specific method
                    args.analyze_command = action
                    analyze_cli.handle_command(args)
                else:
                    # Just show the manager object info (consistent with shell)
                    manager = getattr(backend, action)
                    print(manager)
            else:
                print(f"Error: Unknown action '{action}'", file=sys.stderr)
                sys.exit(1)
        elif action is None:
            # No action specified - show helpful information about the binary
            _show_analyze_help(backend)

    except FileNotFoundError as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"Error loading binary: {e}", file=sys.stderr)
        sys.exit(1)


def _show_analyze_help(analyzer):
    """Show helpful information about what can be done with the binary."""
    from ..cli.analyze import AnalyzeCLI

    analyze_cli = AnalyzeCLI()

    print("\nBinary analysis loaded. Available actions:")
    print("  shell      - Start interactive shell")

    # Dynamically discover available managers
    for manager_name in analyze_cli.manager_classes:
        if manager_name != "backend_name":  # Skip non-manager properties
            print(f"  {manager_name:<10} - Access {manager_name} manager")


def _handle_config_command_dynamic(args):
    """Handle config command using the package API."""
    import ludi

    config_obj = ludi.config
    subcommand = getattr(args, "config_command", None)

    if not subcommand:
        print("Error: No config subcommand specified", file=sys.stderr)
        sys.exit(1)

    try:
        method = getattr(config_obj, subcommand)

        # Build kwargs from args
        import inspect

        sig = inspect.signature(method)
        kwargs = {}

        for param_name in sig.parameters:
            if param_name == "self":
                continue

            # Convert CLI arg names back to method parameter names
            arg_name = param_name.replace("_", "-")
            if hasattr(args, arg_name.replace("-", "_")):
                kwargs[param_name] = getattr(args, arg_name.replace("-", "_"))
            elif hasattr(args, param_name):
                kwargs[param_name] = getattr(args, param_name)

        method(**kwargs)

    except AttributeError:
        print(f"Error: Unknown config command: {subcommand}", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"Config error: {e}", file=sys.stderr)
        sys.exit(1)


def _handle_analyze_command(args):
    """Handle the 'analyze' command."""
    binary_path = args.binary
    backend = args.backend

    if not os.path.exists(binary_path):
        print(f"Error: Binary '{binary_path}' not found", file=sys.stderr)
        sys.exit(1)

    # Create analyzer and start binary shell
    import ludi

    try:
        if backend:
            analyzer = ludi.analyze(binary_path, backend=backend)
        else:
            analyzer = ludi.auto(binary_path)

        print(f"Loaded binary: {binary_path}")
        print(f"Using backend: {analyzer.backend_name}")

        _start_binary_shell(analyzer, binary_path)
    except Exception as e:
        print(f"Error loading binary: {e}", file=sys.stderr)
        sys.exit(1)


class MainShellCompleter:
    def __init__(self):
        self.commands = self._discover_shell_commands()
        self.current_candidates = []

    def _discover_shell_commands(self):
        """Use shared function to discover shell commands"""
        return _discover_shell_commands()

    def complete(self, text, state):
        if state == 0:
            line = readline.get_line_buffer()
            parts = line.split()

            if parts and parts[0] == "load" and len(parts) > 1:
                self.current_candidates = _complete_file_path(text)
            else:
                self.current_candidates = [
                    cmd for cmd in self.commands if cmd.startswith(text)
                ]

        try:
            return self.current_candidates[state]
        except IndexError:
            return None


def _start_interactive_shell():
    _display_ascii_art()
    print()
    print("LUDI Interactive Shell")
    if READLINE_AVAILABLE:
        print("Tab completion enabled")
        completer = MainShellCompleter()
        readline.set_completer(completer.complete)
        readline.parse_and_bind("tab: complete")
        try:
            readline.read_history_file(Path.home() / ".ludi_history")
        except (OSError, FileNotFoundError):
            pass

    print("Commands mirror CLI structure: 'analyze', 'config', 'help', 'exit'")
    print("Type 'help' for examples or use shortcuts like 'a' for analyze")
    print()

    try:
        while True:
            try:
                command = input("ludi> ").strip()
                if not command:
                    continue

                # Handle special shell commands
                if command in ["exit", "quit"]:
                    break
                elif command == "help":
                    _print_shell_help()
                else:
                    # Process command using CLI structure
                    _execute_shell_command(command)

            except KeyboardInterrupt:
                print("\nUse 'exit' to quit")
            except EOFError:
                print()
                break
    finally:
        if READLINE_AVAILABLE:
            try:
                readline.write_history_file(Path.home() / ".ludi_history")
            except (OSError, PermissionError):
                pass

    print("Goodbye!")


def _discover_binary_managers(analyzer):
    """Shared function to discover managers from analyzer"""
    managers = {}

    # Dynamically discover all manager attributes
    for name in dir(analyzer):
        if not name.startswith("_"):
            try:
                attr = getattr(
                    analyzer, name
                )  # Use analyzer to get through __getattr__
                # Check if it's a manager by checking if it has callable methods that look like manager methods
                if attr and hasattr(attr, "__class__"):
                    methods = [
                        n
                        for n in dir(attr)
                        if not n.startswith("_") and callable(getattr(attr, n))
                    ]
                    # Consider it a manager if it has multiple manager-like methods
                    manager_methods = [
                        m
                        for m in methods
                        if m
                        in [
                            "all",
                            "by_name",
                            "by_address",
                            "strings",
                            "types",
                            "variables",
                            "segments",
                            "imports",
                            "exports",
                            "entry_points",
                            "sections",
                            "file_info",
                        ]
                    ]
                    if len(manager_methods) >= 2:  # Has at least 2 manager methods
                        managers[name] = methods
            except AttributeError:
                # Skip if attribute can't be accessed
                continue

    return managers


class BinaryShellCompleter:
    def __init__(self, analyzer):
        self.analyzer = analyzer
        self.managers = _discover_binary_managers(analyzer)
        control_commands = _discover_binary_shell_commands()
        self.commands = control_commands + list(self.managers.keys())
        self.current_candidates = []

    def complete(self, text, state):
        if state == 0:
            line = readline.get_line_buffer()
            parts = line.split()

            # If no parts or still typing the first word
            if not parts or (len(parts) == 1 and not line.endswith(" ")):
                self.current_candidates = [
                    cmd for cmd in self.commands if cmd.startswith(text)
                ]
            # If we have a manager name and a space after it (ready for method)
            elif len(parts) == 1 and line.endswith(" ") and parts[0] in self.managers:
                manager_methods = self.managers[parts[0]]
                self.current_candidates = [
                    method for method in manager_methods if method.startswith(text)
                ]
            # If typing second word (method name)
            elif len(parts) == 2 and parts[0] in self.managers:
                manager_methods = self.managers[parts[0]]
                self.current_candidates = [
                    method for method in manager_methods if method.startswith(text)
                ]
            else:
                self.current_candidates = []

        try:
            return self.current_candidates[state]
        except IndexError:
            return None


def _start_binary_shell(analyzer, binary_path):
    print(f"Binary shell for: {binary_path}")

    # Create completer to discover managers
    if READLINE_AVAILABLE:
        print("Tab completion enabled")
        completer = BinaryShellCompleter(analyzer)
        readline.set_completer(completer.complete)
        readline.parse_and_bind("tab: complete")
    else:
        completer = BinaryShellCompleter(analyzer)

    # Display discovered managers dynamically
    managers = list(completer.managers.keys())
    if managers:
        print(f"Available managers: {', '.join(sorted(managers))}")

    print("Type 'help' for commands or 'back' to return to main shell")
    print()

    while True:
        try:
            command = input(f"ludi:{Path(binary_path).name}> ").strip()
            if not command:
                continue

            if command in ["back", "exit"]:
                break
            elif command == "help":
                _print_binary_shell_help(analyzer)
            else:
                _execute_binary_command(analyzer, command)

        except KeyboardInterrupt:
            print("\nUse 'back' to return or 'exit' to quit")
        except EOFError:
            print()
            break


def get_completions(words, current_word_index):
    if not words:
        return []

    current_word = words[current_word_index] if current_word_index < len(words) else ""

    if len(words) == 1 and (
        current_word.startswith("/") or current_word.startswith("./")
    ):
        return _complete_file_path(current_word)

    if len(words) == 1:
        commands = ["config", "shell", "completion", "native", "backends"]
        try:
            from .analyze import AnalyzeCLI

            analyze_cli = AnalyzeCLI()
            commands.extend(
                [
                    name
                    for name in analyze_cli.manager_classes.keys()
                    if name != "backend_name"
                ]
            )
        except ImportError:
            # Fallback - check if base managers module exists
            import importlib.util

            if importlib.util.find_spec("ludi.backends.base.managers"):
                # Basic managers are available
                commands.extend(["functions", "binary", "symbols", "xrefs"])
        return [cmd for cmd in commands if cmd.startswith(current_word)]

    cmd = words[0]

    if cmd == "config" and len(words) == 2:
        subcommands = ["show", "discover", "set", "test", "reset"]
        return [sub for sub in subcommands if sub.startswith(current_word)]

    if cmd == "config" and len(words) == 3 and words[1] == "set":
        from ..core.utils import get_config_manager

        config_manager = get_config_manager()
        backends = list(config_manager.load_config().keys())
        return [b for b in backends if b.startswith(current_word)]

    if cmd == "completion" and len(words) == 2:
        shells = ["bash", "zsh", "fish"]
        return [s for s in shells if s.startswith(current_word)]

    if cmd == "native":
        if len(words) == 2:
            return ["run"]
        elif len(words) >= 3 and words[1] == "run":
            if "--backend" in words:
                backend_idx = words.index("--backend")
                if backend_idx + 1 < len(words):
                    return _complete_file_path(
                        current_word, extensions=[".py", ".java", ".js"]
                    )
                else:
                    from ..core.utils import get_config_manager

                    config_manager = get_config_manager()
                    backends = list(config_manager.load_config().keys())
                    return [
                        backend
                        for backend in backends
                        if backend.startswith(current_word)
                    ]
            elif current_word == "--backend" or (
                len(words) >= 4 and words[-2] == "--backend"
            ):
                from ..core.utils import get_config_manager

                config_manager = get_config_manager()
                backends = list(config_manager.load_config().keys())
                return [
                    backend for backend in backends if backend.startswith(current_word)
                ]
            elif current_word.startswith("--"):
                return ["--backend", "--args"]
            else:
                if not any(w.startswith("--backend") for w in words):
                    return ["--backend"]
                return _complete_file_path(
                    current_word, extensions=[".py", ".java", ".js"]
                )

    try:
        from .analyze import AnalyzeCLI

        analyze_cli = AnalyzeCLI()
        if cmd in analyze_cli.manager_classes:
            if len(words) == 2:
                return _complete_file_path(current_word)
            elif len(words) == 3:
                binary_path = words[1] if len(words) > 1 else None
                if binary_path and os.path.exists(binary_path):
                    try:
                        analyze_cli.init_analyzer(binary_path)
                        methods = analyze_cli.get_runtime_methods(cmd)
                    except Exception:
                        manager_class = analyze_cli.manager_classes[cmd]
                        methods = [
                            name
                            for name in dir(manager_class)
                            if not name.startswith("_")
                            and callable(getattr(manager_class, name, None))
                        ]
                else:
                    manager_class = analyze_cli.manager_classes[cmd]
                    methods = [
                        name
                        for name in dir(manager_class)
                        if not name.startswith("_")
                        and callable(getattr(manager_class, name, None))
                    ]

                return [method for method in methods if method.startswith(current_word)]
    except Exception:
        pass

    return []


def _complete_file_path(partial_path, extensions=None):
    if not partial_path:
        partial_path = "."

    try:
        path = Path(partial_path)
        if path.is_dir():
            candidates = []
            for item in path.iterdir():
                item_path = str(item)
                if item.is_dir():
                    item_path += "/"
                    candidates.append(item_path)
                elif not extensions or any(
                    item.name.endswith(ext) for ext in extensions
                ):
                    candidates.append(item_path)
            return candidates
        else:
            parent = path.parent
            name_prefix = path.name
            candidates = []
            try:
                for item in parent.iterdir():
                    if item.name.startswith(name_prefix):
                        item_path = str(item)
                        if item.is_dir():
                            item_path += "/"
                            candidates.append(item_path)
                        elif not extensions or any(
                            item.name.endswith(ext) for ext in extensions
                        ):
                            candidates.append(item_path)
            except (OSError, PermissionError):
                pass
            return candidates
    except (OSError, PermissionError):
        return []


def _generate_completion(shell_type):
    if shell_type == "bash":
        _generate_bash_completion()
    elif shell_type == "zsh":
        print("# ZSH completion not yet implemented")
        sys.exit(1)
    elif shell_type == "fish":
        print("# Fish completion not yet implemented")
        sys.exit(1)


def __complete_command():
    pass


def _start_server(host, port):
    logger.info(f"Server functionality not implemented (would start on {host}:{port})")


def _discover_shell_commands():
    """Discover shell commands using same system as CLI."""
    from ..core import discover_commands

    commands = discover_commands()
    shell_commands = list(commands.keys()) + ["help", "exit"]
    return shell_commands


def _execute_shell_command(command):
    """Execute a shell command using the same discovery and structure as CLI."""
    try:
        # Parse the command into arguments
        args = command.split()
        if not args:
            return

        # Discover available commands using same system as CLI
        from ..core import discover_commands

        discovered_commands = discover_commands()
        shell_commands = list(discovered_commands.keys()) + ["help", "exit"]

        # Expand shorthand commands for shell
        first_arg = args[0]
        matches = [cmd for cmd in shell_commands if cmd.startswith(first_arg)]
        if len(matches) == 1:
            args[0] = matches[0]

        expanded_args = args
        first_arg = expanded_args[0] if expanded_args else ""

        if first_arg == "analyze":
            _handle_shell_analyze_command(expanded_args)
        elif first_arg == "config":
            _handle_shell_config_command(expanded_args)
        elif first_arg in discovered_commands:
            print(
                f"Command '{first_arg}' is available but not yet implemented in shell mode"
            )
        else:
            print(f"Unknown command: {first_arg}")
            available_cmds = ", ".join(shell_commands)
            print(f"Available commands: {available_cmds}")
            print("Use shortcuts: 'a' for analyze, 'c' for config")

    except Exception as e:
        print(f"Command error: {e}")


def _handle_shell_analyze_command(args):
    """Handle analyze command in shell using package API."""
    if len(args) < 2:
        print("Usage: analyze [--backend BACKEND] <binary>")
        return

    binary_path = None
    backend = None

    # Parse arguments
    i = 1
    while i < len(args):
        if args[i] == "--backend" and i + 1 < len(args):
            backend = args[i + 1]
            i += 2
        elif not args[i].startswith("-"):
            binary_path = args[i]
            i += 1
        else:
            i += 1

    if not binary_path:
        print("Error: No binary path provided")
        return

    if not os.path.exists(binary_path):
        print(f"Error: Binary '{binary_path}' not found")
        return

    # Use the same package API as CLI
    import ludi

    try:
        analyzer = ludi.analyze(binary_path, backend=backend)
        print(f"Loaded binary: {binary_path}")
        print(f"Using backend: {analyzer.backend_name}")
        _start_binary_shell(analyzer, binary_path)
    except Exception as e:
        print(f"Error loading binary: {e}")


def _handle_shell_config_command(args):
    """Handle config command in shell using package API."""
    if len(args) < 2:
        print("Usage: config <show|discover|set|test|reset> [args...]")
        return

    import ludi

    config_obj = ludi.config
    subcommand = args[1]

    try:
        if subcommand == "show":
            config_obj.show()
        elif subcommand == "discover":
            config_obj.discover()
        elif subcommand == "test":
            backend = args[2] if len(args) > 2 else None
            config_obj.test(backend=backend)
        elif subcommand == "set":
            print("Config set not yet supported in shell mode")
        elif subcommand == "reset":
            print("Config reset not yet supported in shell mode")
        else:
            print(f"Unknown config subcommand: {subcommand}")
    except Exception as e:
        print(f"Config error: {e}")


def _print_shell_help():
    """Print help for shell commands that mirror CLI structure."""
    print("Available commands (dynamically discovered, consistent with CLI):")
    print()

    # Get commands from discovery system
    from ..core import discover_commands

    discovered_commands = discover_commands()

    commands = []
    for cmd_name in discovered_commands.keys():
        if cmd_name == "analyze":
            commands.append(("analyze", "Analyze a binary file"))
        elif cmd_name == "config":
            commands.append(("config", "Configuration management"))
        else:
            commands.append((cmd_name, f"{cmd_name.title()} command"))

    commands.extend([("help", "Show this help message"), ("exit", "Exit LUDI shell")])

    for cmd, desc in commands:
        print(f"  {cmd:<10} - {desc}")

    print()
    print("Examples:")
    print("  analyze /bin/ls                 # Auto-select backend")
    print("  analyze --backend angr /bin/ls  # Use specific backend")
    print("  config show                     # Show configuration")
    print("  a /bin/ls                       # Shorthand for 'analyze'")
    print("  c show                          # Shorthand for 'config show'")


def _list_available_backends():
    from ..core.utils import get_config_manager

    manager = get_config_manager()
    available_backends = manager.get_available_backend_configs()
    all_backends = list(manager._config.keys()) if manager._loaded else []

    if not all_backends:
        manager.load_config()
        all_backends = list(manager._config.keys())

    print(
        f"Available backends ({len(available_backends)}/{len(all_backends)}):",
        ", ".join(available_backends),
    )


def _discover_binary_shell_commands():
    """Discover binary shell commands using shared utility"""
    from ..core.utils import discover_commands_from_function

    fallback = ["help", "back", "exit"]
    return discover_commands_from_function(_start_binary_shell, fallback)


def _print_binary_shell_help(analyzer=None):
    # Get available managers using shared discovery
    managers = []
    if analyzer:
        discovered_managers = _discover_binary_managers(analyzer)
        managers = list(discovered_managers.keys())

    # Get control commands dynamically
    control_commands = _discover_binary_shell_commands()

    # Display help
    print("Available commands:")
    if managers:
        print(f"  Managers: {', '.join(sorted(managers))}")
    print(f"  Control: {', '.join(sorted(control_commands))}")
    print("\nUsage: <manager> <method> [args...]")
    if managers:
        # Use first manager as example
        example_manager = sorted(managers)[0]
        print(f"Example: {example_manager} all")
    print("\nType manager name + TAB to see available methods")


def _display_result(result):
    from ..core.utils import display_result

    display_result(result)


def _execute_binary_command(analyzer, command):
    parts = command.strip().split()
    if not parts:
        return

    manager_name = parts[0].lower()
    method_name = parts[1] if len(parts) > 1 else None

    # Parse --key=value style arguments
    kwargs = {}
    args = []
    for arg in parts[2:]:
        if arg.startswith("--") and "=" in arg:
            key, value = arg[2:].split("=", 1)
            kwargs[key] = value
        else:
            args.append(arg)

    if hasattr(analyzer, manager_name):
        manager = getattr(analyzer, manager_name)

        if method_name:
            if hasattr(manager, method_name):
                method = getattr(manager, method_name)
                if callable(method):
                    try:
                        result = method(*args, **kwargs)
                        _display_result(result)
                    except Exception as e:
                        print(f"Error: {e}")
                else:
                    print(f"{method_name} is not callable")
            else:
                print(f"No method {method_name}")
        else:
            print(manager)
    else:
        print(f"Unknown: {manager_name}")


def _generate_bash_completion():
    pass
