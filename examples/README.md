# LUDI Examples

Practical reverse engineering scripts using LUDI.

## Scripts

### `find_crypto.py`
Find cryptographic functions in a binary.
```bash
python find_crypto.py /path/to/binary
```

### `large_functions.py`  
Find unusually large functions that may need attention.
```bash
python large_functions.py /path/to/binary [min_size]
```

### `find_strings.py`
Extract URLs, file paths, and other interesting strings.
```bash
python find_strings.py /path/to/binary
```

### `call_graph.py`
Analyze function call relationships.
```bash
# Show most called functions
python call_graph.py /path/to/binary

# Analyze specific function
python call_graph.py /path/to/binary function_name
```

### `suspicious_apis.py`
Find potentially suspicious Windows API calls.
```bash
python suspicious_apis.py /path/to/binary
```

### `function_stats.py`
Quick function statistics and largest functions.
```bash
python function_stats.py /path/to/binary
```

### `configuration_example.py`
Shows how to configure LUDI backends.

## Setup

Activate the virtualenv and configure your decompiler:
```bash
workon ludi
export LUDI_IDA_PATH="/path/to/ida/idat64"
```

## Usage Pattern

All scripts follow the same pattern:
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