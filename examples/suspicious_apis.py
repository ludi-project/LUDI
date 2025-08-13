#!/usr/bin/env python3
"""Find potentially suspicious API calls."""

import sys
import ludi

binary_path = sys.argv[1] if len(sys.argv) > 1 else "/bin/ls"
analyzer = ludi.auto(binary_path)

suspicious_apis = {
    'Process': ['CreateProcess', 'TerminateProcess', 'OpenProcess'],
    'Registry': ['RegSetValue', 'RegDeleteKey', 'RegOpenKey'],
    'File': ['CreateFile', 'DeleteFile', 'WriteFile'],
    'Memory': ['VirtualAlloc', 'VirtualProtect', 'WriteProcessMemory'],
    'Network': ['InternetOpen', 'InternetConnect', 'HttpSendRequest'],
    'Crypto': ['CryptEncrypt', 'CryptDecrypt', 'CryptGenKey']
}

found = {category: [] for category in suspicious_apis}

for symbol in analyzer.symbols:
    if hasattr(symbol, 'name') and symbol.name:
        for category, apis in suspicious_apis.items():
            for api in apis:
                if api.lower() in symbol.name.lower():
                    found[category].append(symbol.name)
                    break

for category, apis in found.items():
    if apis:
        print(f"{category}:")
        for api in apis[:3]:  # Show max 3 per category
            print(f"  {api}")