#!/usr/bin/env python3
"""Quick function statistics."""

import sys
import ludi

binary_path = sys.argv[1] if len(sys.argv) > 1 else "/bin/ls"
analyzer = ludi.auto(binary_path)

functions = analyzer.functions
sizes = [f.size for f in functions if f.size]
named = [f for f in functions if f.name and not f.name.startswith('sub_')]

if sizes:
    avg_size = sum(sizes) / len(sizes)
    print(f"Functions: {len(functions)} total, {len(named)} named")
    print(f"Size: avg {avg_size:.0f}, max {max(sizes)}, min {min(sizes)} bytes")
    
    # Show largest functions
    large_funcs = sorted([f for f in functions if f.size], key=lambda x: x.size, reverse=True)[:3]
    print("Largest functions:")
    for func in large_funcs:
        name = func.name or f"sub_{func.start:x}"
        print(f"  {name} ({func.size} bytes)")