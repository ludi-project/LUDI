#!/usr/bin/env python3
"""Debug angr decompilation issues."""

import sys
import traceback
from pathlib import Path

# Add LUDI to path
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

import ludi

def debug_angr_decompilation():
    """Debug angr decompilation workflow."""
    binary_path = "/bin/ls"  # Common binary for testing
    
    print("Debugging angr decompilation...")
    print(f"Binary: {binary_path}")
    
    try:
        # Initialize angr analyzer
        print("\n1. Initializing angr analyzer...")
        analyzer = ludi.LUDI("angr", binary_path)
        print("   ✓ angr analyzer initialized successfully")
        
        # Get available levels
        print("\n2. Checking available decompilation levels...")
        levels = analyzer.functions.get_available_levels()
        print(f"   Available levels: {levels}")
        
        # Get some functions
        print("\n3. Getting functions...")
        functions = analyzer.functions.get_all()
        print(f"   Found {len(functions)} functions")
        
        if not functions:
            print("   ✗ No functions found!")
            return
        
        # Test decompilation on a few functions
        print("\n4. Testing decompilation on first few functions...")
        
        for i, func in enumerate(functions[:3]):  # Test first 3 functions
            func_name = func.name or f"sub_{func.start:x}"
            print(f"\n   Function {i+1}: {func_name} @ 0x{func.start:x}")
            
            # Try each available level
            for level in levels:
                print(f"     Testing level: {level}")
                try:
                    code = analyzer.functions.get_decompiled_code(func.start, level=level)
                    if code:
                        print(f"       ✓ Success! Got {len(code)} characters")
                        print(f"       Preview: {repr(code[:100])}...")
                    else:
                        print(f"       ✗ No code returned")
                except Exception as e:
                    print(f"       ✗ Error: {e}")
                    if "normalized function graphs" in str(e):
                        print(f"       --> This is the error we're debugging!")
                        
                        # Let's examine the native function object
                        print(f"       Native function: {func._native}")
                        if hasattr(func._native, 'graph'):
                            print(f"       Function has graph: {hasattr(func._native, 'graph')}")
                        
                        # Try to understand what angr needs
                        print(f"       Trying to debug angr requirements...")
                        try:
                            # Get the native angr project
                            angr_project = analyzer.functions.angr.project
                            
                            # Check if we need to normalize the function
                            native_func = func._native
                            if native_func:
                                print(f"       Function basic blocks: {len(native_func.blocks)}")
                                print(f"       Function normalized: {getattr(native_func, 'normalized', 'unknown')}")
                                
                                # Try to normalize it
                                try:
                                    if hasattr(native_func, 'normalize'):
                                        print(f"       Trying to normalize function...")
                                        native_func.normalize()
                                        print(f"       ✓ Function normalized successfully")
                                        
                                        # Try decompilation again
                                        code = analyzer.functions.get_decompiled_code(func.start, level=level)
                                        if code:
                                            print(f"       ✓ Decompilation succeeded after normalization!")
                                        else:
                                            print(f"       ✗ Still no code after normalization")
                                    else:
                                        print(f"       Function doesn't have normalize method")
                                except Exception as norm_e:
                                    print(f"       ✗ Normalization failed: {norm_e}")
                        except Exception as debug_e:
                            print(f"       Debug error: {debug_e}")
                    
                    traceback.print_exc()
        
        print("\n5. Summary of findings...")
        
    except Exception as e:
        print(f"Failed to initialize analyzer: {e}")
        traceback.print_exc()

if __name__ == "__main__":
    debug_angr_decompilation()