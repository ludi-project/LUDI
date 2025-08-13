#!/usr/bin/env python3
"""Verify that the angr pseudocode fix works end-to-end."""

import sys
from pathlib import Path

# Add LUDI to path
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

import ludi

def verify_angr_fix():
    """Verify the angr decompilation fix works."""
    binary_path = "/bin/ls"
    
    print("=== ANGR PSEUDOCODE DECOMPILATION VERIFICATION ===")
    print(f"Binary: {binary_path}")
    
    # Test the direct LUDI interface
    analyzer = ludi.LUDI("angr", binary_path)
    
    # Get functions
    functions = analyzer.functions.get_all()
    print(f"\nFound {len(functions)} functions")
    
    # Test several functions to show it works
    test_functions = functions[:5]
    success_count = 0
    
    print("\nTesting pseudocode decompilation:")
    print("-" * 50)
    
    for i, func in enumerate(test_functions, 1):
        func_name = func.name or f"sub_{func.start:x}"
        print(f"\n[{i}] {func_name} @ 0x{func.start:x}")
        
        # Get pseudocode
        try:
            code = func.get_decompiled_code(level="pseudocode")
            if code and code.strip():
                success_count += 1
                lines = code.strip().split('\n')
                print("     ✓ SUCCESS - Pseudocode generated:")
                for line in lines[:8]:  # Show first 8 lines
                    print(f"       {line}")
                if len(lines) > 8:
                    print(f"       ... ({len(lines) - 8} more lines)")
            else:
                print("     ✗ No pseudocode generated")
        except Exception as e:
            print(f"     ✗ Error: {e}")
    
    print(f"\n{'-' * 50}")
    print(f"RESULTS: {success_count}/{len(test_functions)} functions successfully decompiled")
    
    if success_count == len(test_functions):
        print("🎉 ALL TESTS PASSED - ANGR PSEUDOCODE DECOMPILATION IS WORKING!")
    elif success_count > 0:
        print("⚠️  PARTIAL SUCCESS - Some functions decompiled successfully")
    else:
        print("❌ ALL TESTS FAILED - Issue not resolved")
    
    # Show the available levels
    print(f"\nAvailable decompilation levels: {analyzer.functions.get_available_levels()}")
    
    return success_count == len(test_functions)

if __name__ == "__main__":
    success = verify_angr_fix()
    sys.exit(0 if success else 1)