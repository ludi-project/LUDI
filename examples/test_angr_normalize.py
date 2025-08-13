#!/usr/bin/env python3
"""Test angr function normalization before decompilation."""

import sys
from pathlib import Path
import angr

def test_angr_normalization():
    """Test the manual angr normalization process."""
    binary_path = "/bin/ls"
    
    print("Testing angr normalization...")
    print(f"Binary: {binary_path}")
    
    # Create angr project
    project = angr.Project(binary_path, auto_load_libs=False)
    
    # Generate CFG
    cfg = project.analyses.CFGFast()
    
    # Get a function to test with
    functions = list(cfg.functions.values())
    if not functions:
        print("No functions found!")
        return
    
    # Test with the first few functions
    for i, func in enumerate(functions[:5]):
        func_name = func.name or f"sub_{func.addr:x}"
        print(f"\nTesting function {i+1}: {func_name} @ 0x{func.addr:x}")
        
        # Check if function has blocks
        blocks = list(func.blocks)
        if not blocks:
            print("  No blocks found, skipping...")
            continue
            
        print(f"  Function has {len(blocks)} blocks")
        
        # Try decompilation without normalization
        print("  Trying decompilation without normalization...")
        try:
            # Disable angr's resilience for this test to catch the actual exception
            import logging
            logging.getLogger('angr.analyses.analysis').setLevel(logging.CRITICAL)
            
            dec = project.analyses.Decompiler(func, fail_fast=True)
            if dec.codegen and dec.codegen.text:
                print("  ✓ Decompilation succeeded WITHOUT normalization!")
                print(f"  Preview: {repr(dec.codegen.text[:100])}...")
            else:
                print("  No code generated")
        except ValueError as e:
            if "normalized function graphs" in str(e):
                print("  ✗ Got the normalization error as expected")
                
                # Now try with normalization
                print("  Trying with normalization...")
                try:
                    # Normalize the function
                    func.normalize()
                    print("  ✓ Function normalized successfully")
                    
                    # Try decompilation again
                    dec = project.analyses.Decompiler(func, fail_fast=True)
                    if dec.codegen and dec.codegen.text:
                        print("  ✓ Decompilation succeeded AFTER normalization!")
                        print(f"  Preview: {repr(dec.codegen.text[:100])}...")
                    else:
                        print("  Still no code after normalization")
                        
                except Exception as norm_e:
                    print(f"  ✗ Normalization or decompilation failed: {norm_e}")
            else:
                print(f"  ✗ Different error: {e}")
        except Exception as e:
            print(f"  ✗ Unexpected error: {e}")

if __name__ == "__main__":
    test_angr_normalization()