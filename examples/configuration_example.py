"""
Example demonstrating LUDI's configuration management system.

This shows the layered configuration approach:
1. Environment variables (highest priority)
2. Config files (~/.ludi/config.yaml) 
3. Programmatic API
4. Auto-discovery (lowest priority)
"""

import os
import ludi
from ludi.decompilers.base.config import get_config_manager

# Import decompilers to trigger auto-registration
import ludi.decompilers  # This auto-registers all providers

# Example 1: Environment variable configuration (highest priority)
print("=== Example 1: Environment Variables ===")
os.environ["LUDI_IDA_PATH"] = "/home/han/bin/idat64"
os.environ["LUDI_DEFAULT_BACKEND"] = "ida"

# The config system will pick this up automatically
config_manager = get_config_manager()
config = config_manager.load()
ida_config = config_manager.get_backend_config('ida')
print(f"IDA path from env: {ida_config.path}")
print(f"Default backend from env: {config.default_backend}")

# Example 2: Programmatic configuration
print("\n=== Example 2: Programmatic Configuration ===")
config_manager.set_backend_path('ida', '/home/han/bin/idat64')
print(f"IDA path set programmatically: {config_manager.get_backend_config('ida').path}")

# Example 3: Auto-discovery (now handled by each provider)
print("\n=== Example 3: Auto-Discovery ===")
providers = config_manager.get_providers()
print("Discovered tools:")
for provider in providers:
    discovered_path = provider.auto_discover()
    status = "✓" if discovered_path else "✗"
    print(f"  {status} {provider.backend_name.upper()}: {discovered_path or 'Not found'}")

# Example 4: Configuration validation
print("\n=== Example 4: Configuration Validation ===")
validation = config_manager.validate()
print("Validation results:")
for backend, valid in validation.items():
    status = "✓ Valid" if valid else "✗ Invalid"
    print(f"  {backend}: {status}")

# Example 5: Available backends through LUDI
print("\n=== Example 5: Available Backends ===")
available = ludi.LUDI.get_available_backends()
print(f"Available backends: {available}")

if available:
    print(f"Auto-detected backend would be: {available[0]}")
    
    # Example 6: Using auto-detection
    print("\n=== Example 6: Auto-Detection in Action ===")
    try:
        # This will use the first available backend
        analyzer = ludi.auto("/bin/yes")
        print(f"Successfully created analyzer with backend: {analyzer.backend_name}")
        functions = analyzer.functions.get_all()
        print(f"Found {len(functions)} functions")
    except Exception as e:
        print(f"Auto-detection failed: {e}")

# Example 7: Config file management
print("\n=== Example 7: Config File Management ===")
print(f"Config file location: {config_manager.CONFIG_FILE}")
print(f"Config file exists: {config_manager.CONFIG_FILE.exists()}")

# Save current configuration
config_manager.save()
print("Configuration saved to file")

# Example 8: Modular provider system
print("\n=== Example 8: Modular Provider System ===")
print("Registered providers:")
for provider in providers:
    print(f"  - {provider.backend_name}: {type(provider).__name__}")
    print(f"    Available: {provider.is_available()}")
    print(f"    Config: {provider.get_config()}")

print("\n=== CLI Commands You Can Run ===")
print("# Show current configuration:")
print("python -m ludi.cli.main config show --validate")
print("\n# Auto-discover and save tools:")
print("python -m ludi.cli.main config discover --save")
print("\n# Set IDA path manually:")
print("python -m ludi.cli.main config set ida --path /path/to/idat64")
print("\n# Test installations:")
print("python -m ludi.cli.main config test")