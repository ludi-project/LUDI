import argparse
import os
import sys
from pathlib import Path

from .. import ludi
from ..assets import get_banner, get_title
from ..logger import get_logger, setup_logging
from .analyze import AnalyzeCLI
from .config import ConfigCLI

logger = get_logger("cli.main")

try:
    import readline

    READLINE_AVAILABLE = True
except ImportError:
    READLINE_AVAILABLE = False


def _display_ascii_art():
    print(get_banner())


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
            from ludi.decompilers.base.config import get_config_manager

            config_manager = get_config_manager()
            providers = config_manager.get_providers()

            for provider in providers:
                if provider.auto_discover():
                    backend = provider.backend_name
                    break
        except (ImportError, AttributeError):
            from ludi.decompilers.base.config import get_config_manager

            config_manager = get_config_manager()
            available = config_manager.get_available_backends()
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
        from ludi.decompilers.base.config import get_config_manager

        config_manager = get_config_manager()

        if backend in config_manager._providers:
            provider = config_manager._providers[backend]
            provider.run_script(script_path, binary_path, script_args)
        else:
            print(f"Error: Script execution not supported for backend '{backend}'", file=sys.stderr)
            sys.exit(1)
    except Exception as e:
        print(f"Error running {backend} script: {e}", file=sys.stderr)
        sys.exit(1)


def main():
    temp_parser = argparse.ArgumentParser(add_help=False)
    temp_parser.add_argument("--debug", action="store_true")
    temp_parser.add_argument("-v", "--verbose", action="store_true")
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

    if (
        len(sys.argv) > 1
        and (sys.argv[1].startswith("/") or sys.argv[1].startswith("./"))
        and not any(
            arg in sys.argv
            for arg in [
                "native",
                "config",
                "shell",
                "completion",
                "functions",
                "symbols",
                "xrefs",
                "binary",
            ]
        )
    ):
        _handle_binary_execution()
        return

    parser = argparse.ArgumentParser(
        prog="ludi", description=get_title(), formatter_class=argparse.RawDescriptionHelpFormatter
    )

    from ludi.decompilers.base.config import get_config_manager

    config_manager = get_config_manager()
    available_backends = list(config_manager.load_config().keys())
    parser.add_argument(
        "--backend",
        choices=available_backends,
        help="Backend to use (default: from config/env/auto-discovery)",
    )
    parser.add_argument("--binary", help="Binary file to analyze")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose output")
    parser.add_argument("--debug", action="store_true", help="Enable debug logging")

    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    config_parser = subparsers.add_parser("config", help="Configuration management")
    config_cli = ConfigCLI()

    config_subparsers = config_parser.add_subparsers(dest="config_command")

    show_parser = config_subparsers.add_parser("show", help="Show configuration")
    show_parser.add_argument("--validate", action="store_true", help="Validate configuration")

    discover_parser = config_subparsers.add_parser("discover", help="Auto-discover tools")
    discover_parser.add_argument("--save", action="store_true", help="Save discovered paths")

    set_parser = config_subparsers.add_parser("set", help="Set configuration")
    set_parser.add_argument("backend", help="Backend to configure")
    set_parser.add_argument("--path", help="Path to executable")
    set_parser.add_argument("--enabled", type=bool, help="Enable/disable")
    set_parser.add_argument("--default", action="store_true", help="Set as default")

    test_parser = config_subparsers.add_parser("test", help="Test installations")
    test_parser.add_argument("backend", nargs="?", help="Backend to test (default: all)")

    reset_parser = config_subparsers.add_parser("reset", help="Reset configuration")
    reset_parser.add_argument("--confirm", action="store_true", help="Confirm reset")

    subparsers.add_parser("shell", help="Interactive LUDI shell")

    server_parser = subparsers.add_parser("server", help="Run LUDI server")
    server_parser.add_argument("--host", default="0.0.0.0", help="Server host (default: 0.0.0.0)")
    server_parser.add_argument("--port", type=int, default=8080, help="Server port (default: 8080)")

    completion_parser = subparsers.add_parser("completion", help="Generate completion scripts")
    completion_parser.add_argument(
        "shell_type", choices=["bash", "zsh", "fish"], help="Shell type to generate completion for"
    )

    native_parser = subparsers.add_parser("native", help="Run native backend scripts")
    native_subparsers = native_parser.add_subparsers(
        dest="native_action", help="Native script actions"
    )

    run_parser = native_subparsers.add_parser(
        "run",
        help="Run a native script",
        description="Run native scripts using backend-specific environments.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    run_parser.add_argument("script", help="Script file to execute")
    run_parser.add_argument("binary", nargs="?", help="Binary file to analyze (optional)")
    run_parser.add_argument("--args", nargs="*", help="Additional arguments to pass to script")

    analyze_cli = AnalyzeCLI()

    for manager_name, manager_class in analyze_cli.manager_classes.items():
        manager_parser = subparsers.add_parser(
            manager_name, help=f"{manager_name.title()} analysis"
        )
        manager_parser.add_argument(
            "binary", nargs="?", help="Binary file to analyze (optional if --binary used)"
        )
        manager_sub = manager_parser.add_subparsers(
            dest=f"{manager_name}_action", help=f"{manager_name.title()} methods"
        )
        analyze_cli._add_method_parsers(manager_sub, manager_name, manager_class)

    args = parser.parse_args()

    if not args.command:
        _display_ascii_art()
        print()
        parser.print_help()
        return

    if args.command == "config":
        if not args.config_command:
            config_parser.print_help()
            return

        try:
            if args.config_command == "show":
                config_cli.show_config(validate=args.validate)
            elif args.config_command == "discover":
                config_cli.discover_tools(save=args.save)
            elif args.config_command == "set":
                config_cli.set_config(
                    backend=args.backend, path=args.path, enabled=args.enabled, default=args.default
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
            native_parser.print_help()
            return
        elif args.native_action == "run":
            backend, binary = _resolve_backend_and_binary(args)
            target_binary = binary or getattr(args, "binary", None)
            _run_native_script(backend, args.script, target_binary, args.args or [])

    elif args.command == "completion":
        _generate_completion(args.shell_type)

    elif args.command in analyze_cli.manager_classes:
        backend, binary = _resolve_backend_and_binary(args)

        target_binary = binary or args.binary
        if not target_binary:
            print(
                "Error: No binary specified. Use --binary flag or provide as positional argument.",
                file=sys.stderr,
            )
            sys.exit(1)

        args.backend = backend
        args.binary = target_binary

        args.analyze_command = args.command
        setattr(args, f"{args.command}_action", getattr(args, f"{args.command}_action", None))

        try:
            analyze_cli.handle_command(args)
        except Exception as e:
            print(f"Error: {e}", file=sys.stderr)
            sys.exit(1)


def _handle_binary_execution():
    binary_path = None
    backend = None
    remaining_args = []

    args = sys.argv[1:]
    i = 0
    while i < len(args):
        if args[i] == "--binary":
            if i + 1 < len(args):
                binary_path = args[i + 1]
                i += 2
            else:
                print("Error: --binary requires a path", file=sys.stderr)
                sys.exit(1)
        elif args[i] == "--backend":
            if i + 1 < len(args):
                backend = args[i + 1]
                i += 2
            else:
                print("Error: --backend requires a backend name", file=sys.stderr)
                sys.exit(1)
        elif args[i].startswith("/") or args[i].startswith("./"):
            if binary_path is None:
                binary_path = args[i]
            else:
                remaining_args.append(args[i])
            i += 1
        else:
            remaining_args.append(args[i])
            i += 1

    if not binary_path:
        print("Error: No binary path specified", file=sys.stderr)
        sys.exit(1)

    if not os.path.exists(binary_path):
        print(f"Error: Binary not found: {binary_path}", file=sys.stderr)
        sys.exit(1)

    try:
        if backend:
            analyzer = ludi.LUDI(backend, binary_path)
        else:
            analyzer = ludi.LUDI("auto", binary_path)

        print(f"Loaded binary: {binary_path}")
        print(f"Using backend: {analyzer.backend_name}")

        _start_binary_shell(analyzer, binary_path)

    except Exception as e:
        print(f"Error loading binary: {e}", file=sys.stderr)
        sys.exit(1)


class MainShellCompleter:
    def __init__(self):
        self.commands = ["help", "exit", "quit", "load"]
        self.current_candidates = []

    def complete(self, text, state):
        if state == 0:
            line = readline.get_line_buffer()
            parts = line.split()

            if parts and parts[0] == "load" and len(parts) > 1:
                self.current_candidates = _complete_file_path(text)
            else:
                self.current_candidates = [cmd for cmd in self.commands if cmd.startswith(text)]

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

    print("Type 'help' for commands or 'exit' to quit")
    print()

    try:
        while True:
            try:
                command = input("ludi> ").strip()
                if not command:
                    continue

                if command in ["exit", "quit"]:
                    break
                elif command == "help":
                    _print_shell_help()
                elif command == "backends":
                    _list_available_backends()
                elif command.startswith("load "):
                    parts = command[5:].strip().split()
                    if not parts:
                        print(
                            "Usage: load <binary_path> [backend_name] or load <binary_path> --backend <backend_name>"
                        )
                        continue

                    binary_path = parts[0]
                    backend = None

                    if len(parts) >= 2:
                        if parts[1] == "--backend" and len(parts) >= 3:
                            backend = parts[2]
                        else:
                            backend = parts[1]

                    if os.path.exists(binary_path):
                        try:
                            if backend:
                                analyzer = ludi.LUDI(backend, binary_path)
                                print(f"Loaded: {binary_path} (backend: {analyzer.backend_name})")
                            else:
                                analyzer = ludi.LUDI("auto", binary_path)
                                print(
                                    f"Loaded: {binary_path} (auto-selected: {analyzer.backend_name})"
                                )
                            _start_binary_shell(analyzer, binary_path)
                        except Exception as e:
                            if backend:
                                print(f"Error loading binary with {backend} backend: {e}")
                                _list_available_backends()
                            else:
                                print(f"Error loading binary: {e}")
                    else:
                        print(f"Binary not found: {binary_path}")
                else:
                    print(f"Unknown command: {command}. Type 'help' for available commands.")

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


class BinaryShellCompleter:
    def __init__(self, analyzer):
        self.analyzer = analyzer
        self.managers = {}
        
        # Try to get the underlying decompiler for more accurate discovery
        underlying_decompiler = getattr(analyzer, '_decompiler', analyzer)
        
        # Dynamically discover all manager attributes
        for name in dir(underlying_decompiler):
            if not name.startswith("_"):
                try:
                    attr = getattr(analyzer, name)  # Use analyzer to get through __getattr__
                    # Check if it's a manager by checking if it has callable methods that look like manager methods
                    if attr and hasattr(attr, '__class__'):
                        methods = [
                            n
                            for n in dir(attr)
                            if not n.startswith("_") and callable(getattr(attr, n))
                        ]
                        # Consider it a manager if it has multiple manager-like methods
                        manager_methods = [m for m in methods if m in ['all', 'by_name', 'by_address', 'strings', 'types', 'variables', 'segments', 'imports', 'exports', 'entry_points', 'sections']]
                        if len(manager_methods) >= 2:  # Has at least 2 manager methods
                            self.managers[name] = methods
                except AttributeError:
                    # Skip if attribute can't be accessed
                    continue

        self.commands = ["help", "back", "exit"] + list(self.managers.keys())
        self.current_candidates = []

    def complete(self, text, state):
        if state == 0:
            line = readline.get_line_buffer()
            parts = line.split()

            # If no parts or still typing the first word
            if not parts or (len(parts) == 1 and not line.endswith(' ')):
                self.current_candidates = [cmd for cmd in self.commands if cmd.startswith(text)]
            # If we have a manager name and a space after it (ready for method)
            elif len(parts) == 1 and line.endswith(' ') and parts[0] in self.managers:
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
    print("Available managers: functions, symbols, xrefs, binary")
    if READLINE_AVAILABLE:
        print("Tab completion enabled")
        completer = BinaryShellCompleter(analyzer)
        readline.set_completer(completer.complete)
        readline.parse_and_bind("tab: complete")

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

    if len(words) == 1 and (current_word.startswith("/") or current_word.startswith("./")):
        return _complete_file_path(current_word)

    if len(words) == 1:
        commands = ["config", "shell", "completion", "native", "backends"]
        try:
            from .analyze import AnalyzeCLI

            analyze_cli = AnalyzeCLI()
            commands.extend(analyze_cli.manager_classes.keys())
        except ImportError:
            commands.extend(["functions", "symbols", "xrefs", "binary"])
        return [cmd for cmd in commands if cmd.startswith(current_word)]

    cmd = words[0]

    if cmd == "config" and len(words) == 2:
        subcommands = ["show", "discover", "set", "test", "reset"]
        return [sub for sub in subcommands if sub.startswith(current_word)]

    if cmd == "config" and len(words) == 3 and words[1] == "set":
        from ludi.decompilers.base.config import get_config_manager

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
                    return _complete_file_path(current_word, extensions=[".py", ".java", ".js"])
                else:
                    from ludi.decompilers.base.config import get_config_manager

                    config_manager = get_config_manager()
                    backends = list(config_manager.load_config().keys())
                    return [backend for backend in backends if backend.startswith(current_word)]
            elif current_word == "--backend" or (len(words) >= 4 and words[-2] == "--backend"):
                from ludi.decompilers.base.config import get_config_manager

                config_manager = get_config_manager()
                backends = list(config_manager.load_config().keys())
                return [backend for backend in backends if backend.startswith(current_word)]
            elif current_word.startswith("--"):
                return ["--backend", "--args"]
            else:
                if not any(w.startswith("--backend") for w in words):
                    return ["--backend"]
                return _complete_file_path(current_word, extensions=[".py", ".java", ".js"])

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
                        if not name.startswith("_") and callable(getattr(manager_class, name, None))
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
                elif not extensions or any(item.name.endswith(ext) for ext in extensions):
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
                        elif not extensions or any(item.name.endswith(ext) for ext in extensions):
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
    logger.info("Server functionality not implemented")


def _print_shell_help():
    # Dynamically discover commands by looking at the shell handler patterns
    commands = []
    
    # Scan the _start_interactive_shell function source for command patterns
    import inspect
    try:
        source = inspect.getsource(_start_interactive_shell)
        lines = source.split('\n')
        
        for line in lines:
            line = line.strip()
            # Find command handlers
            if 'command ==' in line and '"' in line:
                # Extract command from: elif command == "help":
                start = line.find('"') + 1
                end = line.find('"', start)
                if start > 0 and end > start:
                    cmd = line[start:end]
                    if cmd not in ["exit", "quit"] and cmd not in commands:
                        commands.append(cmd)
            elif 'command.startswith(' in line and '"' in line:
                # Extract command from: elif command.startswith("load "):
                start = line.find('"') + 1
                end = line.find(' ', start)
                if end == -1:
                    end = line.find('"', start)
                if start > 0 and end > start:
                    cmd = line[start:end]
                    if cmd not in commands:
                        commands.append(cmd)
            elif 'command in [' in line:
                # Handle special cases like: if command in ["exit", "quit"]:
                continue
                        
    except Exception:
        # Fallback to known commands
        commands = ["help", "backends", "load"]
    
    # Always add core commands
    commands.extend(["exit", "quit"])
    print("Available commands:", ", ".join(sorted(set(commands))))


def _list_available_backends():
    from ..decompilers.base.config import get_config_manager
    
    manager = get_config_manager()
    available_backends = manager.get_available_backends()
    all_backends = list(manager._config.keys()) if manager._loaded else []
    
    if not all_backends:
        manager.load_config()
        all_backends = list(manager._config.keys())
    
    print(f"Available backends ({len(available_backends)}/{len(all_backends)}):", ", ".join(available_backends))


def _print_binary_shell_help(analyzer=None):
    # Get available managers dynamically
    managers = []
    if analyzer:
        underlying_decompiler = getattr(analyzer, '_decompiler', analyzer)
        for name in dir(underlying_decompiler):
            if not name.startswith("_"):
                try:
                    attr = getattr(analyzer, name)  # Use analyzer to get through __getattr__
                    # Check if it's a manager by checking if it has get_* methods
                    if attr and hasattr(attr, '__class__'):
                        methods = [
                            n
                            for n in dir(attr)
                            if not n.startswith("_") and callable(getattr(attr, n))
                        ]
                        manager_methods = [m for m in methods if m in ['all', 'by_name', 'by_address', 'strings', 'types', 'variables', 'segments', 'imports', 'exports', 'entry_points', 'sections']]
                        if len(manager_methods) >= 2:  # Has at least 2 manager methods
                            managers.append(name)
                except AttributeError:
                    continue
    
    # Get control commands
    control_commands = ["help", "back", "exit"]
    
    # Display help
    print("Available commands:")
    print(f"  Managers: {', '.join(managers)}")
    print(f"  Control: {', '.join(control_commands)}")
    print("\nUsage: <manager> <method> [args...]")
    print("Example: functions get_by_name main")
    print("\nType manager name + TAB to see available methods")


def _display_result(result):
    if result is None:
        print("None")
    elif isinstance(result, (list, tuple)):
        if not result:
            print("[]")
        else:
            for item in result:
                _display_item(item)
    else:
        _display_item(result)

def _display_item(item):
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
        print(str(item))

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
