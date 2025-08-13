<p align="center">
  <img alt="LUDI" src="https://github.com/DennyDai/LUDI/raw/main/ludi.svg" width="128">
</p>
<h1 align="center">LUDI Unifies Decompiler Interface</h1>

[![Latest Release](https://img.shields.io/pypi/v/ludi.svg)](https://pypi.python.org/pypi/ludi/)
[![PyPI Statistics](https://img.shields.io/pypi/dm/ludi.svg)](https://pypistats.org/packages/ludi)
[![License](https://img.shields.io/github/license/DennyDai/ludi.svg)](https://github.com/DennyDai/ludi/blob/main/LICENSE)

LUDI provides a unified interface for reverse engineering tools including IDA Pro, Ghidra, and angr. Write once, analyze anywhere.

## ⚠️ Development Status

This project is in **early development**. APIs may change significantly before version 1.0.0. The codebase currently contains AI-generated code that is not yet fully reviewed. Version 1.0.0 will be fully reviewed and stable.

## Quick Start

```bash
pip install ludi

# Analyze with auto-detected backend
ludi /bin/ls functions get_all

# Use specific backend  
ludi --backend ida /bin/ls functions get_decompiled_code main

# Interactive shell
ludi shell
```

```python
import ludi

analyzer = ludi.auto("/path/to/binary")

# Simple, clean iteration
for func in analyzer.functions:
    print(func.name, hex(func.start))

for symbol in analyzer.symbols:
    print(symbol.name)

for xref in analyzer.xrefs:
    print(hex(xref.from_addr), "->", hex(xref.to_addr))
```

## Contributing

Contributions are welcome! Please feel free to submit pull requests and open issues for bugs, features, or suggestions.