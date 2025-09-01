<p align="center">
  <img alt="LUDI" src="https://github.com/ludi-project/LUDI/raw/main/ludi.svg" width="128">
</p>
<h1 align="center">LUDI Unifies Decompiler Interface</h1>

[![Latest Release](https://img.shields.io/pypi/v/ludi.svg)](https://pypi.python.org/pypi/ludi/)
[![PyPI Statistics](https://img.shields.io/pypi/dm/ludi.svg)](https://pypistats.org/packages/ludi)
[![License](https://img.shields.io/github/license/ludi-project/ludi.svg)](https://github.com/ludi-project/ludi/blob/main/LICENSE)

LUDI provides a unified interface for reverse engineering tools including IDA Pro, Ghidra, and angr. Write once, analyze anywhere.

## DO NOT USE THIS PROJECT (YET)
> [!WARNING]
> This project is in **very early development**. APIs may **change significantly** before version 1.0.0. The codebase currently **contains AI-generated code** that is **not yet fully reviewed**. Version 1.0.0 will be fully reviewed and stable.

## Installation

```bash
pip install ludi                    # Core only
pip install ludi[all]               # All backends
```

## Quick Start

### CLI
```bash
ludi analyze /bin/ls                # Auto-select backend
ludi analyze --backend ida /bin/ls  # Use specific backend
ludi shell                          # Interactive shell
ludi config show                    # Show configuration
```

### Python API
```python
import ludi

# Simple analysis
analyzer = ludi.analyze("/bin/ls")  # Auto-select best backend
# OR
analyzer = ludi.ida("/bin/ls")      # Use specific backend
# OR
analyzer = ludi.analyze("/bin/ls", backend="ida-local")  # Use named config
```

### Usage

```python
# Unified API across all backends
for func in analyzer.functions:
    print(f"{func.name}: {hex(func.start)}")
    print(analyzer.functions.decompiled_code(func.start))

# Access managers
analyzer.functions      # Function analysis
analyzer.symbols        # Symbol information
analyzer.xrefs          # Cross-references
analyzer.binary         # Binary metadata
analyzer.types          # Type information
analyzer.architecture   # CPU architecture
analyzer.memory         # Memory operations
```

## Configuration

LUDI uses named configurations in `~/.config/ludi/config.yaml`:

```yaml
ida-local:
  type: ida
  path: /opt/ida-pro/
  enabled: true

angr:
  type: angr
  autodiscover: true
```

## Contributing

Contributions are welcome! Please feel free to submit pull requests and open issues for bugs, features, or suggestions.
