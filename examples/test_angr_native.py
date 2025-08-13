#!/usr/bin/env python3
"""
Example native angr script for LUDI native runner.
Usage: ludi native run --backend angr test_angr_native.py [/path/to/binary]
"""

import os
import sys

def main():
    print("=== LUDI Native angr Script ===")
    print(f"Python executable: {sys.executable}")
    print(f"Script arguments: {sys.argv[1:]}")
    
    # Get binary path from environment variable (set by LUDI native runner)
    binary_path = os.environ.get('LUDI_BINARY_PATH')
    if binary_path:
        print(f"Target binary: {binary_path}")
    else:
        print("No target binary specified")
    
    # Try to import and use angr
    try:
        import angr
        print(f"angr version: {angr.__version__}")
        
        if binary_path:
            print(f"Loading binary with angr...")
            project = angr.Project(binary_path, auto_load_libs=False)
            print(f"Architecture: {project.arch}")
            print(f"Entry point: 0x{project.entry:x}")
            
            # Simple CFG analysis
            print("Performing CFG analysis...")
            cfg = project.analyses.CFGFast()
            print(f"Found {len(cfg.functions)} functions")
            
            # List first few functions
            for i, (addr, func) in enumerate(cfg.functions.items()):
                if i >= 5:  # Only show first 5
                    break
                print(f"  Function @ 0x{addr:x}: {func.name or 'unnamed'}")
        
    except ImportError:
        print("ERROR: angr not available in this environment")
        return 1
    except Exception as e:
        print(f"ERROR: {e}")
        return 1
    
    print("=== Script completed successfully ===")
    return 0

if __name__ == '__main__':
    sys.exit(main())