#!/usr/bin/env python3
"""Test the angr decompilation fix."""

import sys
from pathlib import Path

# Add LUDI to path
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

import ludi

def test_angr_decompilation_fix():
    """Test that angr pseudocode decompilation now works."""
    binary_path = "/bin/ls"
    
    print("Testing angr decompilation fix...")
    print(f"Binary: {binary_path}")
    
    try:
        # Initialize angr analyzer
        analyzer = ludi.LUDI("angr", binary_path)
        
        # Get functions
        functions = analyzer.functions.get_all()
        print(f"Found {len(functions)} functions")
        
        # Test pseudocode decompilation on first few functions
        success_count = 0
        total_tested = 0
        
        for func in functions[:10]:  # Test first 10 functions
            func_name = func.name or f"sub_{func.start:x}"
            print(f"\nTesting {func_name} @ 0x{func.start:x}")
            
            try:
                # Test pseudocode level specifically
                code = analyzer.functions.get_decompiled_code(func.start, level="pseudocode")
                if code and code.strip():
                    print(f"  ✓ Success! Got pseudocode ({len(code)} characters)")
                    print(f"  Preview: {repr(code[:200])}...")
                    success_count += 1
                else:
                    print(f"  ✗ No pseudocode returned")
                
                total_tested += 1
                
            except Exception as e:
                print(f"  ✗ Error: {e}")
                total_tested += 1
        
        print(f"\nResults: {success_count}/{total_tested} functions successfully decompiled to pseudocode")
        
        if success_count > 0:
            print("✅ ANGR PSEUDOCODE DECOMPILATION IS NOW WORKING!")
        else:
            print("❌ ANGR PSEUDOCODE DECOMPILATION STILL NOT WORKING")
            
    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    test_angr_decompilation_fix()