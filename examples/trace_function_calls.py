#!/usr/bin/env python3
"""Trace function calls - demonstrates linking xrefs with functions."""

import sys
import ludi

binary_path = sys.argv[1] if len(sys.argv) > 1 else "/bin/ls"
analyzer = ludi.auto(binary_path)

def trace_function_calls(func_name):
    """Show what a function calls and what calls it."""
    # Find the function
    func = analyzer.functions.get_by_name(func_name)
    if not func:
        print(f"Function '{func_name}' not found")
        return
    
    print(f"=== Analysis of {func.name} @ 0x{func.start:x} ===")
    
    # Get decompiled code
    code = analyzer.functions.get_decompiled_code(func.start)
    if code:
        print(f"\nDecompiled code:")
        print(code[:200] + "..." if len(code) > 200 else code)
    
    # Get all xrefs for this function
    xrefs = analyzer.xrefs.get_function_xrefs(func.start)
    
    print(f"\nCalled by {len(xrefs['calls_to'])} functions:")
    for xref in xrefs['calls_to'][:5]:  # Show first 5
        caller_func = analyzer.functions.get_function_containing(xref.from_addr)
        caller_name = caller_func.name if caller_func and caller_func.name else hex(xref.from_addr)
        print(f"  {caller_name} @ 0x{xref.from_addr:x}")
    
    print(f"\nCalls {len(xrefs['calls_from'])} functions:")
    for xref in xrefs['calls_from'][:5]:  # Show first 5
        target_func = analyzer.functions.get_function_containing(xref.to_addr)
        target_name = target_func.name if target_func and target_func.name else hex(xref.to_addr)
        print(f"  {target_name} @ 0x{xref.to_addr:x}")

# Example usage
trace_function_calls("malloc")
print("\n" + "="*50 + "\n")
trace_function_calls("strcmp")