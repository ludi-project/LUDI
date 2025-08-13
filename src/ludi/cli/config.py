import argparse
import sys
from pathlib import Path
from ..decompilers.base.config import get_config_manager


class ConfigCLI:
    """CLI interface for LUDI configuration management."""
    
    def __init__(self):
        self.config_manager = get_config_manager()
    
    def create_parser(self) -> argparse.ArgumentParser:
        """Create argument parser for config commands."""
        parser = argparse.ArgumentParser(
            prog='ludi config',
            description='LUDI configuration management'
        )
        
        subparsers = parser.add_subparsers(dest='command', help='Configuration commands')
        
        # Show command
        show_parser = subparsers.add_parser('show', help='Show current configuration')
        show_parser.add_argument('--validate', action='store_true', 
                               help='Validate configuration')
        
        # Discover command
        discover_parser = subparsers.add_parser('discover', help='Auto-discover decompilers')
        discover_parser.add_argument('--save', action='store_true', 
                                   help='Save discovered paths to config')
        
        # Set command
        set_parser = subparsers.add_parser('set', help='Set configuration values')
        set_parser.add_argument('backend', help='Backend to configure')
        set_parser.add_argument('--path', help='Path to decompiler executable')
        set_parser.add_argument('--enabled', type=bool, help='Enable/disable backend')
        set_parser.add_argument('--default', action='store_true', 
                              help='Set as default backend')
        
        # Test command
        test_parser = subparsers.add_parser('test', help='Test decompiler installations')
        test_parser.add_argument('backend', nargs='?', 
                               help='Specific backend to test (default: all)')
        
        # Reset command
        reset_parser = subparsers.add_parser('reset', help='Reset configuration')
        reset_parser.add_argument('--confirm', action='store_true', 
                                help='Confirm reset operation')
        
        return parser
    
    def show_config(self, validate: bool = False):
        """Show current configuration."""
        config = self.config_manager.load()
        
        print("LUDI Configuration")
        print("=" * 50)
        
        # Show backend configurations from providers
        providers = self.config_manager.get_providers()
        for provider in providers:
            backend_config = provider.get_config()
            backend_name = provider.backend_name
            print(f"\n{backend_name.upper()}:")
            print(f"  Path: {backend_config.path or 'Not configured'}")
            print(f"  Enabled: {backend_config.enabled}")
            print(f"  Auto-discover: {backend_config.auto_discover}")
            if backend_config.options:
                print(f"  Options: {backend_config.options}")
        
        print(f"\nDefault backend: {config.default_backend or 'Auto-detect'}")
        
        if config.global_options:
            print(f"\nGlobal options: {config.global_options}")
        
        print(f"\nConfig file: {self.config_manager.CONFIG_FILE}")
        print(f"Config file exists: {self.config_manager.CONFIG_FILE.exists()}")
        
        if validate:
            print("\nValidation Results:")
            print("-" * 20)
            validation = self.config_manager.validate()
            for backend, valid in validation.items():
                status = "✓ Valid" if valid else "✗ Invalid"
                print(f"  {backend}: {status}")
    
    def discover_tools(self, save: bool = False):
        """Discover decompiler installations."""
        print("Discovering decompiler installations...")
        print("=" * 40)
        
        providers = self.config_manager.get_providers()
        discovered_any = False
        
        for provider in providers:
            discovered_path = provider.auto_discover()
            if discovered_path:
                print(f"✓ {provider.backend_name.upper()}: {discovered_path}")
                if save:
                    config = provider.get_config()
                    config.path = discovered_path
                    provider.set_config(config)
                    discovered_any = True
            else:
                print(f"✗ {provider.backend_name.upper()}: Not found")
        
        if save and discovered_any:
            self.config_manager.save()
            print(f"\nConfiguration saved to {self.config_manager.CONFIG_FILE}")
        elif save:
            print("\nNo tools discovered, configuration not modified")
        
        # Show system info for debugging
        print("\nSystem Information:")
        print("-" * 20)
        import platform
        import os
        system_info = {
            'platform': platform.system(),
            'architecture': platform.machine(),
            'python_version': platform.python_version(),
            'home_directory': str(Path.home()),
            'path_env': os.environ.get('PATH', ''),
        }
        for key, value in system_info.items():
            if key == 'path_env':
                # Truncate PATH for readability
                value = value[:100] + "..." if len(value) > 100 else value
            print(f"  {key}: {value}")
    
    def set_config(self, backend: str, path: str = None, enabled: bool = None, 
                   default: bool = False):
        """Set configuration values."""
        config = self.config_manager.load()
        backend_config = getattr(config, backend)
        
        changed = False
        
        if path:
            backend_config.path = path
            changed = True
            print(f"Set {backend} path to: {path}")
        
        if enabled is not None:
            backend_config.enabled = enabled
            changed = True
            print(f"Set {backend} enabled to: {enabled}")
        
        if default:
            config.default_backend = backend
            changed = True
            print(f"Set default backend to: {backend}")
        
        if changed:
            self.config_manager.save(config)
            print(f"Configuration saved to {self.config_manager.CONFIG_FILE}")
        else:
            print("No changes made")
    
    def test_installations(self, backend: str = None):
        """Test decompiler installations."""
        config = self.config_manager.load()
        providers = self.config_manager.get_providers()
        
        # Filter providers if specific backend requested
        if backend:
            providers = [p for p in providers if p.backend_name == backend]
            if not providers:
                print(f"Error: Unknown backend '{backend}'")
                return
        
        print("Testing decompiler installations...")
        print("=" * 35)
        
        for provider in providers:
            backend_config = provider.get_config()
            
            if not backend_config.enabled:
                print(f"⊘ {provider.backend_name.upper()}: Disabled")
                continue
            
            valid = provider.validate()
            status = "✓ Working" if valid else "✗ Failed"
            path_info = f" ({backend_config.path})" if backend_config.path else ""
            print(f"{status} {provider.backend_name.upper()}{path_info}")
    
    def reset_config(self, confirm: bool = False):
        """Reset configuration to defaults."""
        if not confirm:
            print("This will delete your configuration file.")
            print("Use --confirm to proceed with reset.")
            return
        
        if self.config_manager.CONFIG_FILE.exists():
            self.config_manager.CONFIG_FILE.unlink()
            print(f"Configuration file deleted: {self.config_manager.CONFIG_FILE}")
        else:
            print("No configuration file to delete")
        
        # Clear cached config
        self.config_manager._loaded = False
        self.config_manager._config = None
        
        print("Configuration reset to defaults")
    
    def run(self, args: list[str] = None):
        """Run the configuration CLI."""
        parser = self.create_parser()
        parsed_args = parser.parse_args(args)
        
        if not parsed_args.command:
            parser.print_help()
            return
        
        try:
            if parsed_args.command == 'show':
                self.show_config(validate=parsed_args.validate)
            elif parsed_args.command == 'discover':
                self.discover_tools(save=parsed_args.save)
            elif parsed_args.command == 'set':
                self.set_config(
                    backend=parsed_args.backend,
                    path=parsed_args.path,
                    enabled=parsed_args.enabled,
                    default=parsed_args.default
                )
            elif parsed_args.command == 'test':
                self.test_installations(backend=parsed_args.backend)
            elif parsed_args.command == 'reset':
                self.reset_config(confirm=parsed_args.confirm)
        except Exception as e:
            print(f"Error: {e}", file=sys.stderr)
            sys.exit(1)


def main():
    """Main entry point for config CLI."""
    cli = ConfigCLI()
    cli.run()