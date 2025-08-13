#!/usr/bin/env python3
"""
Example native IDA Python script for LUDI native runner.
Usage: ludi native run --backend ida test_ida_native.py [/path/to/binary]

This script will be executed within IDA's Python environment.
"""

import sys

def main():
    print("=== LUDI Native IDA Script ===")
    print(f"Script arguments: {sys.argv}")
    
    try:
        # Import IDA Python modules
        import ida_pro
        import ida_kernwin
        import ida_name
        import ida_funcs
        import ida_segment
        
        print(f"IDA Pro version: {ida_pro.IDA_SDK_VERSION}")
        
        # Get basic info about the loaded binary
        import ida_nalt
        inf = ida_nalt.get_inf_structure()
        print(f"File type: {inf.filetype}")
        
        # Get entry point
        entry = inf.start_ea
        print(f"Entry point: 0x{entry:x}")
        
        # Count functions
        func_count = ida_funcs.get_func_qty()
        print(f"Number of functions: {func_count}")
        
        # List first few functions
        print("First 5 functions:")
        for i in range(min(5, func_count)):
            func = ida_funcs.getn_func(i)
            if func:
                name = ida_name.get_ea_name(func.start_ea)
                print(f"  Function @ 0x{func.start_ea:x}: {name or 'unnamed'}")
        
        # Get segments info
        print("\\nSegments:")
        for seg in ida_segment.get_segm_qty():
            segm = ida_segment.getnseg(seg)
            if segm:
                name = ida_segment.get_segm_name(segm)
                print(f"  {name}: 0x{segm.start_ea:x}-0x{segm.end_ea:x}")
        
        print("=== IDA Script completed successfully ===")
        
    except ImportError as e:
        print(f"ERROR: IDA Python modules not available: {e}")
        print("This script should be run within IDA's Python environment")
        return 1
    except Exception as e:
        print(f"ERROR: {e}")
        return 1
    
    return 0

if __name__ == '__main__':
    # In IDA, we call main and then quit
    result = main()
    
    try:
        import ida_pro
        ida_pro.qexit(result)
    except ImportError:
        # Not in IDA environment
        sys.exit(result)