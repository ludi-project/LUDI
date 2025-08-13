#!/usr/bin/env python3
"""Find unusually large functions."""

import sys
import ludi

binary_path = sys.argv[1] if len(sys.argv) > 1 else "/bin/ls"
min_size = int(sys.argv[2]) if len(sys.argv) > 2 else 1000

analyzer = ludi.auto(binary_path)

large_funcs = [f for f in analyzer.functions if f.size and f.size > min_size]
large_funcs.sort(key=lambda x: x.size, reverse=True)

for func in large_funcs:
    name = func.name or f"sub_{func.start:x}"
    print(f"{name:<30} {func.size:>6} bytes @ 0x{func.start:x}")