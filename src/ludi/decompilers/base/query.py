from typing import List, Callable, Any, Union, Optional, TypeVar, Generic, Iterator

T = TypeVar('T')

class Collection(Generic[T]):
    """Simple, clean collection that focuses on iteration and basic operations."""
    
    def __init__(self, source: Union[List[T], Callable[[], List[T]]]):
        self._source = source
    
    def _get_items(self) -> List[T]:
        """Get the actual items (lazy if source is callable)."""
        if callable(self._source):
            return self._source()
        return self._source
    
    # Core iteration - what people actually use
    def __iter__(self) -> Iterator[T]:
        """Main use case: for item in collection:"""
        return iter(self._get_items())
    
    def __len__(self) -> int:
        """len(collection)"""
        return len(self._get_items())
    
    def __getitem__(self, index: Union[int, slice]) -> Union[T, List[T]]:
        """collection[0] or collection[1:5]"""
        return self._get_items()[index]
    
    def __bool__(self) -> bool:
        """if collection:"""
        return len(self._get_items()) > 0
    
    # Simple access methods
    def all(self) -> List[T]:
        """Get all items as list."""
        return self._get_items()
    
    def first(self) -> Optional[T]:
        """Get first item."""
        items = self._get_items()
        return items[0] if items else None
    
    def count(self) -> int:
        """Count items."""
        return len(self._get_items())
    
    # Simple filtering - returns new Collection
    def filter(self, predicate: Callable[[T], bool]) -> "Collection[T]":
        """Filter items - returns new Collection."""
        return Collection([item for item in self._get_items() if predicate(item)])
    
    def sort(self, key: Union[str, Callable[[T], Any]] = None, reverse: bool = False) -> "Collection[T]":
        """Sort items - returns new Collection."""
        items = self._get_items()
        if key is None:
            return Collection(sorted(items, reverse=reverse))
        elif isinstance(key, str):
            return Collection(sorted(items, key=lambda x: getattr(x, key, 0), reverse=reverse))
        else:
            return Collection(sorted(items, key=key, reverse=reverse))
    
    def take(self, count: int) -> "Collection[T]":
        """Take first N items."""
        return Collection(self._get_items()[:count])


# Domain-specific collections that inherit the simple interface
class FunctionCollection(Collection):
    """Functions with some domain-specific helpers."""
    
    def by_name(self, name: str) -> Optional[T]:
        """Find function by name."""
        for func in self:
            if func.name == name:
                return func
        return None
    
    def by_address(self, addr: int) -> Optional[T]:
        """Find function by address."""
        for func in self:
            if func.start <= addr < func.end:
                return func
        return None
    
    def large(self, min_size: int = 1000) -> "FunctionCollection":
        """Get large functions."""
        return FunctionCollection(self.filter(lambda f: f.size >= min_size)._get_items())
    
    def named(self) -> "FunctionCollection":
        """Get named functions."""
        return FunctionCollection(self.filter(lambda f: f.name is not None)._get_items())


class SymbolCollection(Collection):
    """Symbols with domain-specific helpers."""
    
    def by_name(self, name: str) -> Optional[T]:
        """Find symbol by name."""
        for sym in self:
            if sym.name == name:
                return sym
        return None
    
    def by_type(self, symbol_type: str) -> "SymbolCollection":
        """Get symbols of specific type."""
        return SymbolCollection(self.filter(lambda s: s.symbol_type == symbol_type)._get_items())
    
    @property
    def functions(self) -> "SymbolCollection":
        """Get function symbols."""
        return self.by_type("function")
    
    @property
    def imports(self) -> "SymbolCollection":
        """Get import symbols."""
        return self.by_type("import")


class XRefCollection(Collection):
    """XRefs with domain-specific helpers."""
    
    def from_addr(self, addr: int) -> "XRefCollection":
        """Get xrefs from address."""
        return XRefCollection(self.filter(lambda x: x.from_addr == addr)._get_items())
    
    def to_addr(self, addr: int) -> "XRefCollection":
        """Get xrefs to address."""
        return XRefCollection(self.filter(lambda x: x.to_addr == addr)._get_items())
    
    def by_type(self, xref_type: str) -> "XRefCollection":
        """Get xrefs of specific type."""
        return XRefCollection(self.filter(lambda x: x.xref_type == xref_type)._get_items())
    
    @property
    def calls(self) -> "XRefCollection":
        """Get call references."""
        return self.by_type("call")
    
    @property
    def data_refs(self) -> "XRefCollection":
        """Get data references."""
        return XRefCollection(self.filter(lambda x: x.xref_type.startswith("data"))._get_items())


class InstructionCollection(Collection):
    """Instructions with domain-specific helpers."""
    
    def by_address(self, addr: int) -> Optional[T]:
        """Find instruction by address."""
        for instr in self:
            if instr.address == addr:
                return instr
        return None
    
    def by_mnemonic(self, mnemonic: str) -> "InstructionCollection":
        """Get instructions with specific mnemonic."""
        return InstructionCollection(self.filter(lambda i: i.mnemonic == mnemonic)._get_items())
    
    def at_level(self, level: str) -> "InstructionCollection":
        """Get instructions at specific representation level."""
        return InstructionCollection(self.filter(lambda i: i.level == level)._get_items())


class VariableCollection(Collection):
    """Variables with domain-specific helpers."""
    
    def by_name(self, name: str) -> Optional[T]:
        """Find variable by name."""
        for var in self:
            if var.name == name:
                return var
        return None
    
    def by_type(self, var_type: str) -> "VariableCollection":
        """Get variables of specific type."""
        return VariableCollection(self.filter(lambda v: v.var_type == var_type)._get_items())
    
    def in_scope(self, scope: int) -> "VariableCollection":
        """Get variables in specific scope (function)."""
        return VariableCollection(self.filter(lambda v: v.scope == scope)._get_items())
    
    @property
    def locals(self) -> "VariableCollection":
        """Get local variables (scoped to functions)."""
        return VariableCollection(self.filter(lambda v: v.scope is not None)._get_items())
    
    @property
    def globals(self) -> "VariableCollection":
        """Get global variables (not scoped)."""
        return VariableCollection(self.filter(lambda v: v.scope is None)._get_items())


# Utility functions for common operations
def sum_attr(collection: Collection[T], attr: str) -> float:
    """Sum attribute values across collection."""
    return sum(getattr(item, attr, 0) for item in collection if getattr(item, attr, None) is not None)

def avg_attr(collection: Collection[T], attr: str) -> float:
    """Average attribute values."""  
    values = [getattr(item, attr, 0) for item in collection if getattr(item, attr, None) is not None]
    return sum(values) / len(values) if values else 0

def max_attr(collection: Collection[T], attr: str) -> Any:
    """Max attribute value."""
    values = [getattr(item, attr, 0) for item in collection if getattr(item, attr, None) is not None]
    return max(values) if values else None

def to_csv(collection: Collection[T]) -> str:
    """Export collection as CSV."""
    items = collection.all()
    if not items or not hasattr(items[0], 'to_dict'):
        return ""
    
    columns = list(items[0].to_dict().keys())
    lines = [",".join(columns)]
    for item in items:
        data = item.to_dict()
        lines.append(",".join(str(data.get(col, '')) for col in columns))
    return "\n".join(lines)