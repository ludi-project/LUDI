import sys
import argparse
import os
import subprocess
from pathlib import Path
from .config import ConfigCLI
from .analyze import AnalyzeCLI
import ludi
from ..assets import LUDI_ASCII_BANNER, LUDI_TEXT_BANNER

try:
    import readline
    READLINE_AVAILABLE = True
except ImportError:
    READLINE_AVAILABLE = False


def _display_ascii_art():
    """Display LUDI ASCII art banner."""
    try:
        # Try to display colored ASCII art
        print(LUDI_ASCII_BANNER)
    except Exception:
        # If anything goes wrong, show the plain text version
        print(LUDI_TEXT_BANNER)


def _resolve_backend_and_binary(args):
    """Resolve backend and binary with fallback hierarchy: CLI > env > config > auto-discovery."""
    backend = None
    binary = None
    
    # 1. CLI arguments (highest priority)
    if hasattr(args, 'backend') and args.backend:
        backend = args.backend
    if hasattr(args, 'binary') and args.binary:
        binary = args.binary
    
    # 2. Environment variables
    if not backend:
        backend = os.environ.get('LUDI_BACKEND')
    if not binary:
        binary = os.environ.get('LUDI_BINARY')
    
    # 3. Configuration file
    if not backend:
        try:
            from .config import ConfigCLI
            config_cli = ConfigCLI()
            # Try to get default backend from config (this would need to be implemented)
            # For now, we'll skip this step
        except:
            pass
    
    # 4. Auto-discovery (find first available backend)
    if not backend:
        try:
            from ludi.decompilers.base.config import get_config_manager
            config_manager = get_config_manager()
            providers = config_manager.get_providers()
            
            for provider in providers:
                if provider.auto_discover():
                    backend = provider.backend_name
                    break
        except:
            # Fallback to angr as it's most commonly available
            backend = 'angr'
    
    return backend, binary


def _run_native_script(backend: str, script_path: str, binary_path: str = None, script_args: list = None):
    """Run a native script using the specified backend."""
    script_args = script_args or []
    
    # Validate script file exists
    if not os.path.exists(script_path):
        print(f"Error: Script file '{script_path}' not found", file=sys.stderr)
        sys.exit(1)
    
    # Validate binary file exists if provided
    if binary_path and not os.path.exists(binary_path):
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
        if backend == 'ida':
            _run_ida_script(script_path, binary_path, script_args)
        elif backend == 'ghidra':
            _run_ghidra_script(script_path, binary_path, script_args)
        elif backend == 'angr':
            _run_angr_script(script_path, binary_path, script_args)
        else:
            print(f"Error: Unsupported backend '{backend}'", file=sys.stderr)
            sys.exit(1)
    except Exception as e:
        print(f"Error running {backend} script: {e}", file=sys.stderr)
        sys.exit(1)


def _run_ida_script(script_path: str, binary_path: str = None, script_args: list = None):
    """Run IDA Python script using IDA."""
    from ludi.decompilers.ida.config import get_ida_config
    
    config = get_ida_config()
    if not config.path:
        raise ValueError("IDA path not configured. Run 'ludi config discover' or set LUDI_IDA_PATH")
    
    ida_executable = None
    # Find appropriate IDA executable
    ida_dir = Path(config.path)
    for ida_exe in ['idat64', 'idat', 'ida64', 'ida']:
        exe_path = ida_dir / ida_exe
        if exe_path.exists():
            ida_executable = str(exe_path)
            break
    
    if not ida_executable:
        raise ValueError(f"Could not find IDA executable in {ida_dir}")
    
    # Build IDA command
    cmd = [ida_executable, '-A']  # Auto-analyze
    
    if binary_path:
        cmd.append(binary_path)
    else:
        # Create a dummy database if no binary specified
        cmd.extend(['-o/dev/null'])
    
    # Add script
    cmd.extend(['-S', script_path])
    
    # Add script arguments if any
    if script_args:
        # IDA passes additional args to scripts via sys.argv
        cmd.extend(script_args)
    
    print(f"Executing: {' '.join(cmd)}")
    result = subprocess.run(cmd, capture_output=False)
    sys.exit(result.returncode)


def _run_ghidra_script(script_path: str, binary_path: str = None, script_args: list = None):
    """Run Ghidra script using headless analyzer."""
    from ludi.decompilers.ghidra.config import get_ghidra_config
    
    config = get_ghidra_config()
    if not config.headless_path:
        raise ValueError("Ghidra path not configured. Run 'ludi config discover' or set LUDI_GHIDRA_PATH")
    
    # Create temporary project
    import tempfile
    with tempfile.TemporaryDirectory() as temp_dir:
        project_dir = os.path.join(temp_dir, 'ghidra_project')
        
        cmd = [config.headless_path, project_dir, 'temp_project']
        
        if binary_path:
            cmd.extend(['-import', binary_path])
        else:
            cmd.append('-process')  # Process without import
        
        # Add script
        cmd.extend(['-postScript', script_path])
        
        # Add script arguments
        if script_args:
            cmd.extend(script_args)
        
        print(f"Executing: {' '.join(cmd)}")
        result = subprocess.run(cmd, capture_output=False)
        sys.exit(result.returncode)


def _run_angr_script(script_path: str, binary_path: str = None, script_args: list = None):
    """Run angr script in Python environment."""
    import sys
    import subprocess
    
    # Build Python command to run the script
    cmd = [sys.executable, script_path]
    
    # Set environment variables
    env = os.environ.copy()
    
    # Pass binary path as environment variable if provided
    if binary_path:
        env['LUDI_BINARY_PATH'] = binary_path
    
    # Pass script arguments
    if script_args:
        cmd.extend(script_args)
    
    # Add angr to Python path by ensuring ludi is available
    # (since angr scripts will typically import angr)
    print(f"Executing: {' '.join(cmd)}")
    if binary_path:
        print(f"Binary available via environment variable: LUDI_BINARY_PATH={binary_path}")
    
    result = subprocess.run(cmd, env=env, capture_output=False)
    sys.exit(result.returncode)


def main():
    """Main CLI entry point."""
    # Handle hidden completion command first
    if len(sys.argv) > 1 and sys.argv[1] == '__complete':
        __complete_command()
        return
        
    # Check if first arg looks like a binary path (but not if using other commands)
    if (len(sys.argv) > 1 and 
        (sys.argv[1].startswith('/') or sys.argv[1].startswith('./')) and
        not any(arg in sys.argv for arg in ['native', 'config', 'shell', 'completion', 'functions', 'symbols', 'xrefs', 'binary'])):
        _handle_binary_execution()
        return
    
    parser = argparse.ArgumentParser(
        prog='ludi',
        description='LUDI Unifies Decompiler Interface'
    )
    
    # Add global arguments
    parser.add_argument('--backend', choices=['ida', 'ghidra', 'angr'], 
                       help='Backend to use (default: from config/env/auto-discovery)')
    parser.add_argument('--binary', help='Binary file to analyze')
    
    subparsers = parser.add_subparsers(dest='command', help='Available commands')
    
    # Config subcommand
    config_parser = subparsers.add_parser('config', help='Configuration management')
    config_cli = ConfigCLI()
    
    # Add config subcommands
    config_subparsers = config_parser.add_subparsers(dest='config_command')
    
    # Show
    show_parser = config_subparsers.add_parser('show', help='Show configuration')
    show_parser.add_argument('--validate', action='store_true', help='Validate configuration')
    
    # Discover
    discover_parser = config_subparsers.add_parser('discover', help='Auto-discover tools')
    discover_parser.add_argument('--save', action='store_true', help='Save discovered paths')
    
    # Set
    set_parser = config_subparsers.add_parser('set', help='Set configuration')
    set_parser.add_argument('backend', help='Backend to configure')
    set_parser.add_argument('--path', help='Path to executable')
    set_parser.add_argument('--enabled', type=bool, help='Enable/disable')
    set_parser.add_argument('--default', action='store_true', help='Set as default')
    
    # Test
    test_parser = config_subparsers.add_parser('test', help='Test installations')
    test_parser.add_argument('backend', nargs='?', help='Backend to test (default: all)')
    
    # Reset
    reset_parser = config_subparsers.add_parser('reset', help='Reset configuration')
    reset_parser.add_argument('--confirm', action='store_true', help='Confirm reset')
    
    # Shell subcommand
    subparsers.add_parser('shell', help='Interactive LUDI shell')
    
    # Completion subcommand
    completion_parser = subparsers.add_parser('completion', help='Generate completion scripts')
    completion_parser.add_argument('shell_type', choices=['bash', 'zsh', 'fish'], 
                                  help='Shell type to generate completion for')
    
    # Native script runner subcommand
    native_parser = subparsers.add_parser('native', help='Run native backend scripts')
    native_subparsers = native_parser.add_subparsers(dest='native_action', help='Native script actions')
    
    # Run subcommand
    run_parser = native_subparsers.add_parser('run', help='Run a native script',
                                             description='''Run native scripts using backend-specific environments.
Examples:
  ludi --backend ida native run script.py /bin/ls          # Run IDA Python script
  ludi --binary /bin/ls native run --backend angr script.py # Run angr script  
  LUDI_BACKEND=ghidra ludi native run script.py /bin/ls    # Use env variable
  ludi native run script.py /bin/ls                        # Auto-discover backend''',
                                             formatter_class=argparse.RawDescriptionHelpFormatter)
    # Backend will come from global --backend flag
    run_parser.add_argument('script', help='Script file to execute')
    run_parser.add_argument('binary', nargs='?', help='Binary file to analyze (optional)')
    run_parser.add_argument('--args', nargs='*', help='Additional arguments to pass to script')
    
    # Add analysis commands dynamically from manager classes
    analyze_cli = AnalyzeCLI()
    
    # Dynamically create subcommands for each manager
    for manager_name, manager_class in analyze_cli.manager_classes.items():
        manager_parser = subparsers.add_parser(manager_name, help=f'{manager_name.title()} analysis')
        # Binary will come from global --binary flag, but allow positional as fallback
        manager_parser.add_argument('binary', nargs='?', help='Binary file to analyze (optional if --binary used)')
        # Backend will come from global --backend flag
        manager_sub = manager_parser.add_subparsers(dest=f'{manager_name}_action', help=f'{manager_name.title()} methods')
        analyze_cli._add_method_parsers(manager_sub, manager_name, manager_class)
    
    # Parse arguments
    args = parser.parse_args()
    
    if not args.command:
        _display_ascii_art()
        print()
        parser.print_help()
        return
    
    # Handle config commands
    if args.command == 'config':
        if not args.config_command:
            config_parser.print_help()
            return
        
        try:
            if args.config_command == 'show':
                config_cli.show_config(validate=args.validate)
            elif args.config_command == 'discover':
                config_cli.discover_tools(save=args.save)
            elif args.config_command == 'set':
                config_cli.set_config(
                    backend=args.backend,
                    path=args.path,
                    enabled=args.enabled,
                    default=args.default
                )
            elif args.config_command == 'test':
                config_cli.test_installations(backend=args.backend)
            elif args.config_command == 'reset':
                config_cli.reset_config(confirm=args.confirm)
        except Exception as e:
            print(f"Error: {e}", file=sys.stderr)
            sys.exit(1)
    
    # Handle shell command
    elif args.command == 'shell':
        _start_interactive_shell()
    
    # Handle native script command
    elif args.command == 'native':
        if not args.native_action:
            native_parser.print_help()
            return
        elif args.native_action == 'run':
            backend, binary = _resolve_backend_and_binary(args)
            # Use resolved binary or fallback to positional binary argument  
            target_binary = binary or getattr(args, 'binary', None)
            _run_native_script(backend, args.script, target_binary, args.args or [])
    
    # Handle completion command
    elif args.command == 'completion':
        _generate_completion(args.shell_type)
    
    # Handle analysis commands dynamically
    elif args.command in analyze_cli.manager_classes:
        # Resolve global backend and binary
        backend, binary = _resolve_backend_and_binary(args)
        
        # Use resolved binary or fallback to positional binary argument
        target_binary = binary or args.binary
        if not target_binary:
            print(f"Error: No binary specified. Use --binary flag or provide as positional argument.", file=sys.stderr)
            sys.exit(1)
        
        # Set resolved values on args for compatibility
        args.backend = backend
        args.binary = target_binary
        
        # Convert args to look like old analyze format for compatibility
        args.analyze_command = args.command
        setattr(args, f'{args.command}_action', getattr(args, f'{args.command}_action', None))
        
        try:
            analyze_cli.handle_command(args)
        except Exception as e:
            print(f"Error: {e}", file=sys.stderr)
            sys.exit(1)


def _handle_binary_execution():
    """Handle direct binary execution: ludi /bin/ls or ludi --binary /bin/ls"""
    
    # Parse binary path from command line
    binary_path = None
    backend = None
    remaining_args = []
    
    args = sys.argv[1:]
    i = 0
    while i < len(args):
        if args[i] == '--binary':
            if i + 1 < len(args):
                binary_path = args[i + 1]
                i += 2
            else:
                print("Error: --binary requires a path", file=sys.stderr)
                sys.exit(1)
        elif args[i] == '--backend':
            if i + 1 < len(args):
                backend = args[i + 1]
                i += 2
            else:
                print("Error: --backend requires a backend name", file=sys.stderr)
                sys.exit(1)
        elif args[i].startswith('/') or args[i].startswith('./'):
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
        # Initialize LUDI with the binary
        if backend:
            analyzer = ludi.LUDI(backend, binary_path)
        else:
            analyzer = ludi.auto(binary_path)
        
        print(f"Loaded binary: {binary_path}")
        print(f"Using backend: {analyzer.backend_name}")
        
        # Start interactive mode with the analyzer
        _start_binary_shell(analyzer, binary_path)
        
    except Exception as e:
        print(f"Error loading binary: {e}", file=sys.stderr)
        sys.exit(1)


class MainShellCompleter:
    """Autocomplete for main LUDI shell."""
    
    def __init__(self):
        self.commands = ['help', 'exit', 'quit', 'load']
        self.current_candidates = []
    
    def complete(self, text, state):
        """Return the next possible completion for 'text'."""
        if state == 0:
            # First call - generate candidates using shared logic
            line = readline.get_line_buffer()
            parts = line.split()
            
            # Use shared completion logic for load command
            if parts and parts[0] == 'load' and len(parts) > 1:
                self.current_candidates = _complete_file_path(text)
            else:
                # Shell-specific commands
                self.current_candidates = [cmd for cmd in self.commands if cmd.startswith(text)]
        
        try:
            return self.current_candidates[state]
        except IndexError:
            return None
    


def _start_interactive_shell():
    """Start interactive LUDI shell without a binary."""
    _display_ascii_art()
    print()
    print("LUDI Interactive Shell")
    if READLINE_AVAILABLE:
        print("Tab completion enabled")
        completer = MainShellCompleter()
        readline.set_completer(completer.complete)
        readline.parse_and_bind('tab: complete')
        # Enable history
        try:
            readline.read_history_file(Path.home() / '.ludi_history')
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
                    
                if command in ['exit', 'quit']:
                    break
                elif command == 'help':
                    _print_shell_help()
                elif command.startswith('load '):
                    binary_path = command[5:].strip()
                    if os.path.exists(binary_path):
                        try:
                            analyzer = ludi.auto(binary_path)
                            print(f"Loaded: {binary_path} ({analyzer.backend_name})")
                            _start_binary_shell(analyzer, binary_path)
                        except Exception as e:
                            print(f"Error loading binary: {e}")
                    else:
                        print(f"Binary not found: {binary_path}")
                else:
                    print(f"Unknown command: {command}. Type 'help' for available commands.")
                    
            except KeyboardInterrupt:
                print("\nUse 'exit' to quit")
            except EOFError:
                break
    finally:
        # Save history on exit
        if READLINE_AVAILABLE:
            try:
                readline.write_history_file(Path.home() / '.ludi_history')
            except (OSError, PermissionError):
                pass
    
    print("Goodbye!")


class BinaryShellCompleter:
    """Autocomplete for binary LUDI shell."""
    
    def __init__(self, analyzer):
        self.analyzer = analyzer
        self.manager_names = list(analyzer._decompiler.__class__.__dict__.keys())
        # Get actual manager names from the analyzer
        self.managers = {}
        for name in ['functions', 'symbols', 'xrefs', 'binary']:
            if hasattr(analyzer, name):
                manager = getattr(analyzer, name)
                methods = [n for n in dir(manager) if not n.startswith('_') and callable(getattr(manager, n))]
                self.managers[name] = methods
        
        self.commands = ['help', 'back', 'exit'] + list(self.managers.keys())
        self.current_candidates = []
    
    def complete(self, text, state):
        """Return the next possible completion for 'text'."""
        if state == 0:
            # First call - generate candidates
            line = readline.get_line_buffer()
            parts = line.split()
            
            if len(parts) <= 1:
                # Completing command/manager
                self.current_candidates = [cmd for cmd in self.commands if cmd.startswith(text)]
            elif len(parts) == 2 and parts[0] in self.managers:
                # Completing method name
                manager_methods = self.managers[parts[0]]
                self.current_candidates = [method for method in manager_methods if method.startswith(text)]
            else:
                self.current_candidates = []
        
        try:
            return self.current_candidates[state]
        except IndexError:
            return None


def _start_binary_shell(analyzer, binary_path):
    """Start interactive shell with loaded binary."""
    
    print(f"Binary shell for: {binary_path}")
    print("Available managers: functions, symbols, xrefs, binary")
    if READLINE_AVAILABLE:
        print("Tab completion enabled")
        completer = BinaryShellCompleter(analyzer)
        readline.set_completer(completer.complete)
        readline.parse_and_bind('tab: complete')
    
    print("Type 'help' for commands or 'back' to return to main shell")
    print()
    
    while True:
        try:
            command = input(f"ludi:{Path(binary_path).name}> ").strip()
            if not command:
                continue
                
            if command in ['back', 'exit']:
                break
            elif command == 'help':
                _print_binary_shell_help()
            else:
                _execute_binary_command(analyzer, command)
                
        except KeyboardInterrupt:
            print("\nUse 'back' to return or 'exit' to quit")
        except EOFError:
            break


def get_completions(words, current_word_index):
    """Get completions for command line - shared between shell and bash completion."""
    if not words:
        return []
    
    current_word = words[current_word_index] if current_word_index < len(words) else ""
    
    # Handle direct binary execution (ludi /bin/ls style)
    if len(words) == 1 and (current_word.startswith('/') or current_word.startswith('./')):
        return _complete_file_path(current_word)
    
    # Main command completion
    if len(words) == 1:
        commands = ['config', 'shell', 'completion', 'native']
        # Add manager commands dynamically
        try:
            from .analyze import AnalyzeCLI
            analyze_cli = AnalyzeCLI()
            commands.extend(analyze_cli.manager_classes.keys())
        except:
            commands.extend(['functions', 'symbols', 'xrefs', 'binary'])
        return [cmd for cmd in commands if cmd.startswith(current_word)]
    
    cmd = words[0]
    
    # Config command completions
    if cmd == 'config' and len(words) == 2:
        subcommands = ['show', 'discover', 'set', 'test', 'reset']
        return [sub for sub in subcommands if sub.startswith(current_word)]
    
    if cmd == 'config' and len(words) == 3 and words[1] == 'set':
        backends = ['ida', 'ghidra', 'angr']
        return [b for b in backends if b.startswith(current_word)]
    
    # Completion command completions  
    if cmd == 'completion' and len(words) == 2:
        shells = ['bash', 'zsh', 'fish']
        return [s for s in shells if s.startswith(current_word)]
    
    # Native command completions
    if cmd == 'native':
        if len(words) == 2:
            # Complete native subcommands
            return ['run']
        elif len(words) >= 3 and words[1] == 'run':
            # Handle 'native run' completions
            if '--backend' in words:
                # Find backend value index
                backend_idx = words.index('--backend')
                if backend_idx + 1 < len(words):
                    # Backend already specified, complete script files
                    return _complete_file_path(current_word, extensions=['.py', '.java', '.js'])
                else:
                    # Complete backend names
                    backends = ['ida', 'ghidra', 'angr']
                    return [backend for backend in backends if backend.startswith(current_word)]
            elif current_word == '--backend' or (len(words) >= 4 and words[-2] == '--backend'):
                # Complete backend names after --backend
                backends = ['ida', 'ghidra', 'angr']
                return [backend for backend in backends if backend.startswith(current_word)]
            elif current_word.startswith('--'):
                # Complete flag options
                return ['--backend', '--args']
            else:
                # Complete script files or suggest --backend
                if not any(w.startswith('--backend') for w in words):
                    return ['--backend']
                return _complete_file_path(current_word, extensions=['.py', '.java', '.js'])
    
    # Manager command completions
    try:
        from .analyze import AnalyzeCLI
        analyze_cli = AnalyzeCLI()
        if cmd in analyze_cli.manager_classes:
            if len(words) == 2:
                # Complete binary path
                return _complete_file_path(current_word)
            elif len(words) == 3:
                # Complete manager methods - try to get backend-specific methods
                # First try to load analyzer if binary path is valid
                binary_path = words[1] if len(words) > 1 else None
                if binary_path and os.path.exists(binary_path):
                    try:
                        # Try to get runtime methods for the specific backend
                        analyze_cli.init_analyzer(binary_path)
                        methods = analyze_cli.get_runtime_methods(cmd)
                    except:
                        # Fallback to base class methods
                        manager_class = analyze_cli.manager_classes[cmd]
                        methods = [name for name in dir(manager_class) 
                                  if not name.startswith('_') and callable(getattr(manager_class, name, None))]
                else:
                    # No valid binary, use base class methods
                    manager_class = analyze_cli.manager_classes[cmd]
                    methods = [name for name in dir(manager_class) 
                              if not name.startswith('_') and callable(getattr(manager_class, name, None))]
                
                return [method for method in methods if method.startswith(current_word)]
    except Exception as e:
        # Fallback silently
        pass
    
    return []


def _complete_file_path(partial_path, extensions=None):
    """Complete file paths - shared helper."""
    if not partial_path:
        partial_path = '.'
    
    try:
        path = Path(partial_path)
        if path.is_dir():
            # Complete directory contents
            candidates = []
            for item in path.iterdir():
                item_path = str(item)
                if item.is_dir():
                    item_path += '/'
                    candidates.append(item_path)
                elif not extensions or any(item.name.endswith(ext) for ext in extensions):
                    candidates.append(item_path)
            return candidates
        else:
            # Complete partial filename
            parent = path.parent
            name_prefix = path.name
            candidates = []
            try:
                for item in parent.iterdir():
                    if item.name.startswith(name_prefix):
                        item_path = str(item)
                        if item.is_dir():
                            item_path += '/'
                            candidates.append(item_path)
                        elif not extensions or any(item.name.endswith(ext) for ext in extensions):
                            candidates.append(item_path)
            except (OSError, PermissionError):
                pass
            return candidates
    except (OSError, PermissionError):
        return []


def _generate_completion(shell_type):
    """Generate completion script for the specified shell."""
    if shell_type == 'bash':
        _generate_bash_completion()
    elif shell_type == 'zsh':
        print("# ZSH completion not yet implemented")
        sys.exit(1)
    elif shell_type == 'fish':
        print("# Fish completion not yet implemented") 
        sys.exit(1)


def _generate_bash_completion():
    """Generate bash completion script that calls back to ludi."""
    script = '''#!/bin/bash
# Bash completion script for LUDI
# Generated by: ludi completion bash

_ludi_complete() {
    local cur prev words cword
    _init_completion || return
    
    # Call ludi to get completions
    local completions
    completions=$(ludi __complete "${COMP_WORDS[@]:1}" 2>/dev/null)
    
    if [[ -n "$completions" ]]; then
        COMPREPLY=($(compgen -W "$completions" -- "$cur"))
    else
        # Fallback to file completion
        COMPREPLY=($(compgen -f "$cur"))
    fi
}

complete -F _ludi_complete ludi

# Installation instructions:
# Save this script and source it, or save to /etc/bash_completion.d/ludi
# To install: ludi completion bash > /etc/bash_completion.d/ludi
# Or: ludi completion bash > ~/.local/share/bash-completion/completions/ludi
'''
    print(script)


def __complete_command():
    """Hidden command for bash completion - handles completion requests."""
    words = sys.argv[2:]  # Skip 'ludi __complete'
    if not words:
        return
    
    # Get completions using shared logic
    current_word_index = len(words) - 1
    completions = get_completions(words, current_word_index)
    
    # Print completions for bash to use
    for completion in completions:
        print(completion)


def _execute_binary_command(analyzer, command):
    """Execute command in binary context."""
    parts = command.split()
    if not parts:
        return
        
    manager_name = parts[0]
    if manager_name not in ['functions', 'symbols', 'xrefs', 'binary']:
        print(f"Unknown manager: {manager_name}")
        print("Available managers: functions, symbols, xrefs, binary")
        return
    
    manager = getattr(analyzer, manager_name)
    
    if len(parts) == 1:
        # Show available methods
        print(f"Available {manager_name} methods:")
        methods = [name for name in dir(manager) if not name.startswith('_') and callable(getattr(manager, name))]
        for method in sorted(methods):
            print(f"  {method}")
        return
    
    method_name = parts[1]
    if not hasattr(manager, method_name):
        print(f"Unknown method: {method_name}")
        return
    
    method = getattr(manager, method_name)
    try:
        # Simple method call without arguments for now
        result = method()
        _display_result(result)
    except Exception as e:
        print(f"Error executing {manager_name}.{method_name}(): {e}")


def _display_result(result):
    """Display method result."""
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
    """Display a single item."""
    if hasattr(item, 'name') and hasattr(item, 'start'):
        # Function-like object
        print(f"{item.name or 'unnamed'} @ 0x{item.start:x}")
    elif hasattr(item, 'name') and hasattr(item, 'address'):
        # Symbol-like object
        print(f"{item.name} @ 0x{item.address:x}")
    elif hasattr(item, 'from_addr') and hasattr(item, 'to_addr'):
        # XRef-like object
        print(f"0x{item.from_addr:x} -> 0x{item.to_addr:x} ({item.xref_type})")
    elif isinstance(item, dict):
        # Dict result (like segments, sections)
        formatted = ', '.join(f"{k}: {v}" for k, v in item.items())
        print(f"{{{formatted}}}")
    else:
        print(str(item))


def _print_shell_help():
    """Print help for main shell."""
    _display_ascii_art()
    print()
    print("Available commands:")
    print("  load <binary_path>  - Load a binary for analysis")
    print("  help               - Show this help")
    print("  exit               - Exit LUDI shell")


def _print_binary_shell_help():
    """Print help for binary shell."""
    print("Available commands:")
    print("  <manager>          - Show methods for manager (functions, symbols, xrefs, binary)")
    print("  <manager> <method> - Execute method on manager")
    print("  help               - Show this help") 
    print("  back               - Return to main shell")
    print("  exit               - Exit LUDI shell")


if __name__ == '__main__':
    main()