#!/usr/bin/env python3
"""
Dump decompiled code for all functions using all supported LUDI backends.

This script analyzes a binary with each available decompiler backend and dumps
the decompiled code for all functions to organized output directories.

Usage:
    python dump_all_functions.py <binary_path> [--output OUTPUT_DIR] [--backends BACKEND1,BACKEND2]

Example:
    python dump_all_functions.py /bin/ls
    python dump_all_functions.py /bin/ls --output ./decompiled --backends ida,angr
"""

import argparse
import sys
from pathlib import Path
import time
from typing import List, Optional

try:
    import ludi
except ImportError:
    print("Error: Could not import ludi. Make sure you have activated the ludi environment:")
    print("  workon ludi")
    print("  python examples/dump_all_functions.py <binary>")
    sys.exit(1)


class FunctionDumper:
    """Dumps decompiled functions from binaries using multiple backends."""
    
    def __init__(self, binary_path: str, output_dir: str = "decompiled_output"):
        self.binary_path = Path(binary_path)
        self.output_dir = Path(output_dir)
        # Get supported backends from LUDI class
        self.supported_backends = list(ludi.LUDI.SUPPORTED_BACKENDS.keys())
        
        # Validate binary exists
        if not self.binary_path.exists():
            raise FileNotFoundError(f"Binary not found: {binary_path}")
        
        print(f"Binary: {self.binary_path}")
        print(f"Output directory: {self.output_dir}")
        print(f"Supported backends: {', '.join(self.supported_backends)}")
        
    def dump_all_backends(self, specific_backends: Optional[List[str]] = None):
        """Dump functions using all available backends."""
        backends_to_use = specific_backends if specific_backends else self.supported_backends
        
        print(f"\\nProcessing with backends: {', '.join(backends_to_use)}")
        
        for backend in backends_to_use:
            if backend not in self.supported_backends:
                print(f"Warning: Backend '{backend}' not supported. Skipping.")
                continue
                
            print(f"\\n{'='*60}")
            print(f"Processing with {backend.upper()}")
            print(f"{'='*60}")
            
            try:
                self.dump_backend(backend)
            except Exception as e:
                print(f"Error processing with {backend}: {e}")
                continue
    
    def dump_backend(self, backend: str):
        """Dump functions using a specific backend."""
        start_time = time.time()
        
        # Create backend-specific output directory
        backend_dir = self.output_dir / backend
        backend_dir.mkdir(parents=True, exist_ok=True)
        
        try:
            # Initialize analyzer with specific backend
            print(f"Initializing {backend} analyzer...")
            
            # For Ghidra, ensure we have proper configuration
            if backend == 'ghidra':
                import os
                from ludi.decompilers.base.config import get_config_manager
                
                # Check if GHIDRA_INSTALL_DIR is set, if not try to discover
                if not os.environ.get('GHIDRA_INSTALL_DIR'):
                    config_manager = get_config_manager()
                    providers = config_manager.get_providers()
                    
                    for provider in providers:
                        if provider.backend_name == 'ghidra':
                            discovered_path = provider.auto_discover()
                            if discovered_path:
                                print(f"  Setting GHIDRA_INSTALL_DIR to: {discovered_path}")
                                os.environ['GHIDRA_INSTALL_DIR'] = discovered_path
                                break
            
            analyzer = ludi.LUDI(backend, str(self.binary_path))
            
            # Get all functions
            print("Discovering functions...")
            functions = analyzer.functions.get_all()
            print(f"Found {len(functions)} functions")
            
            if not functions:
                print(f"No functions found with {backend}")
                return
            
            # Process each function
            success_count = 0
            error_count = 0
            
            for i, func in enumerate(functions, 1):
                try:
                    func_name = func.name or f"func_{func.start:08x}"
                    
                    # Skip problematic/synthetic functions that won't decompile
                    skip_patterns = ['Unresolvable', 'Thunk', 'Unknown', '_UNKNOWN', '.plt', '.got']
                    if any(pattern in func_name for pattern in skip_patterns):
                        print(f"[{i:3d}/{len(functions)}] Skipping {func_name} @ 0x{func.start:x} (synthetic)")
                        error_count += 1
                        continue
                        
                    print(f"[{i:3d}/{len(functions)}] Processing {func_name} @ 0x{func.start:x}")
                    
                    # Get decompiled code with fallback levels
                    decompiled = None
                    if backend == 'angr':
                        # Try different levels for angr in order of preference
                        for level in ["pseudocode", None, "disassembly"]:
                            try:
                                decompiled = analyzer.functions.get_decompiled_code(func.start, level=level)
                                if decompiled and decompiled.strip():
                                    break
                            except Exception as e:
                                print(f"    Failed level {level}: {e}")
                                continue
                    else:
                        # For IDA/Ghidra, try default first then fallbacks
                        for level in [None, "pseudocode", "disassembly"]:
                            try:
                                decompiled = analyzer.functions.get_decompiled_code(func.start, level=level)
                                if decompiled and decompiled.strip():
                                    break
                            except Exception as e:
                                if level is None:  # Only show error for first attempt
                                    print(f"    Decompilation failed: {e}")
                                continue
                    
                    if decompiled:
                        # Choose appropriate file extension based on backend and content
                        file_ext = self._get_file_extension(backend, decompiled)
                        safe_name = self._sanitize_filename(func_name)
                        output_file = backend_dir / f"{safe_name}_{func.start:08x}.{file_ext}"
                        
                        with open(output_file, 'w', encoding='utf-8') as f:
                            f.write(f"// Function: {func_name}\n")
                            f.write(f"// Address: 0x{func.start:x}\n")
                            f.write(f"// Backend: {backend}\n")
                            f.write(f"// Size: {func.size} bytes\n")
                            f.write(f"\n{decompiled}\n")
                        
                        success_count += 1
                    else:
                        print(f"  Warning: No decompiled code available")
                        error_count += 1
                        
                except Exception as e:
                    print(f"  Error processing function: {e}")
                    error_count += 1
                    continue
            
            elapsed = time.time() - start_time
            print(f"\\n{backend.upper()} Results:")
            print(f"  Successfully decompiled: {success_count}")
            print(f"  Errors/Empty: {error_count}")
            print(f"  Time elapsed: {elapsed:.2f} seconds")
            
            # Create summary file
            summary_file = backend_dir / "summary.txt"
            with open(summary_file, 'w') as f:
                f.write(f"Decompilation Summary\\n")
                f.write(f"==================\\n")
                f.write(f"Binary: {self.binary_path}\\n")
                f.write(f"Backend: {backend}\\n")
                f.write(f"Total functions: {len(functions)}\\n")
                f.write(f"Successfully decompiled: {success_count}\\n")
                f.write(f"Errors/Empty: {error_count}\\n")
                f.write(f"Time elapsed: {elapsed:.2f} seconds\\n")
                f.write(f"\\nFunction List:\\n")
                for func in functions:
                    func_name = func.name or f"func_{func.start:08x}"
                    f.write(f"  {func_name} @ 0x{func.start:x} (size: {func.size})\\n")
            
        except Exception as e:
            print(f"Failed to initialize {backend} analyzer: {e}")
            import traceback
            traceback.print_exc()
            raise
    
    def _sanitize_filename(self, name: str) -> str:
        """Sanitize function name for use as filename."""
        # Replace problematic characters
        name = name.replace('/', '_').replace('\\\\', '_').replace(':', '_')
        name = name.replace('<', '_').replace('>', '_').replace('|', '_')
        name = name.replace('?', '_').replace('*', '_').replace('"', '_')
        
        # Truncate if too long
        if len(name) > 100:
            name = name[:100]
        
        return name
    
    def _get_file_extension(self, backend: str, content: str) -> str:
        """Determine appropriate file extension based on backend and content."""
        # Check content to determine if it's clearly assembly
        content_lower = content.lower()
        
        # Only use .asm if content is clearly low-level assembly with many mnemonics
        assembly_indicators = ['mov ', 'push ', 'call ', 'jmp ', 'ret', 'lea ', 'add ', 'sub ']
        assembly_count = sum(1 for indicator in assembly_indicators if indicator in content_lower)
        
        # If there are many assembly mnemonics and no C-like constructs, it's assembly
        c_indicators = ['if (', 'while (', 'for (', 'return ', '};', 'int ', 'void ', 'char ']
        c_count = sum(1 for indicator in c_indicators if indicator in content_lower)
        
        # Use .asm only if clearly assembly (many mnemonics, few C constructs)
        if assembly_count > 5 and c_count < 2:
            return 'asm'
        
        # Default to .c for decompiled/pseudocode output
        return 'c'


def main():
    parser = argparse.ArgumentParser(
        description="Dump decompiled code for all functions using LUDI backends",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s /bin/ls
  %(prog)s /bin/ls --output ./my_output
  %(prog)s /bin/ls --backends ida,angr
  %(prog)s /bin/ls --backends ghidra --output ./ghidra_only
        """
    )
    
    parser.add_argument(
        'binary',
        help='Path to binary file to analyze'
    )
    
    parser.add_argument(
        '-o', '--output',
        default='decompiled_output',
        help='Output directory (default: decompiled_output)'
    )
    
    parser.add_argument(
        '-b', '--backends',
        help='Comma-separated list of backends to use (default: all available)'
    )
    
    parser.add_argument(
        '-v', '--verbose',
        action='store_true',
        help='Enable verbose output'
    )
    
    args = parser.parse_args()
    
    # Parse backends
    specific_backends = None
    if args.backends:
        specific_backends = [b.strip().lower() for b in args.backends.split(',')]
    
    try:
        # Create dumper and run
        dumper = FunctionDumper(args.binary, args.output)
        dumper.dump_all_backends(specific_backends)
        
        print(f"\\n{'='*60}")
        print("COMPLETED")
        print(f"{'='*60}")
        print(f"Output saved to: {dumper.output_dir}")
        print("\\nDirectory structure:")
        for backend_dir in dumper.output_dir.iterdir():
            if backend_dir.is_dir():
                file_count = len(list(backend_dir.glob('*.c')))
                print(f"  {backend_dir.name}/: {file_count} decompiled files")
        
    except KeyboardInterrupt:
        print("\\nInterrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)


if __name__ == '__main__':
    main()


# LUDI_IDA_PATH=/home/han/ida-pro-9.1/libidalib.so python3 dump_all_functions.py nilu_server.i64 --output ./nilu --backends ida