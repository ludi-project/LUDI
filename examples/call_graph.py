#!/usr/bin/env python3
"""Analyze function call relationships."""

import sys
from collections import defaultdict
import ludi

binary_path = sys.argv[1] if len(sys.argv) > 1 else "/bin/ls"
target_func = sys.argv[2] if len(sys.argv) > 2 else None

analyzer = ludi.auto(binary_path)

if target_func:
    # Find specific function
    target = None
    for func in analyzer.functions:
        if func.name == target_func or hex(func.start) == target_func:
            target = func
            break
    
    if not target:
        print(f"Function '{target_func}' not found")
        exit(1)
        
    print(f"Analysis for {target.name or hex(target.start)}:")
    
    # What calls this function
    callers = analyzer.xrefs.get_xrefs_to(target.start)
    if callers:
        print(f"  Called by: {len(callers)} functions")
        
    # What this function calls
    calls = analyzer.xrefs.get_xrefs_from(target.start)
    if calls:
        print(f"  Calls: {len(calls)} functions")
        
else:
    # Find most connected functions
    call_counts = defaultdict(int)
    for xref in analyzer.xrefs:
        if xref.xref_type == 'call':
            call_counts[xref.to_addr] += 1
    
    top_targets = sorted(call_counts.items(), key=lambda x: x[1], reverse=True)[:5]
    print("Most called functions:")
    for addr, count in top_targets:
        func = analyzer.functions.get_by_address(addr)
        name = func.name if func and func.name else hex(addr)
        print(f"  {name:<30} ({count} calls)")