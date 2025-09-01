from typing import Any, Callable, Generic, Iterator, Optional, TypeVar, Union

T = TypeVar("T")


class Collection(Generic[T]):
    def __init__(self, source: Union[list[T], Callable[[], list[T]]]):
        self._source = source

    def _get_items(self) -> list[T]:
        if callable(self._source):
            return self._source()
        return self._source

    def __iter__(self) -> Iterator[T]:
        return iter(self._get_items())

    def __len__(self) -> int:
        return len(self._get_items())

    def __getitem__(self, index: Union[int, slice]) -> Union[T, list[T]]:
        return self._get_items()[index]

    def __bool__(self) -> bool:
        return len(self._get_items()) > 0

    def all(self) -> list[T]:
        return self._get_items()

    def first(self) -> Optional[T]:
        items = self._get_items()
        return items[0] if items else None

    def count(self) -> int:
        return len(self._get_items())

    def filter(self, predicate: Callable[[T], bool]) -> "Collection[T]":
        return Collection([item for item in self._get_items() if predicate(item)])

    def sort(
        self, key: Union[str, Callable[[T], Any]] = None, reverse: bool = False
    ) -> "Collection[T]":
        items = self._get_items()
        if key is None:
            return Collection(sorted(items, reverse=reverse))
        elif isinstance(key, str):
            return Collection(
                sorted(items, key=lambda x: getattr(x, key, 0), reverse=reverse)
            )
        else:
            return Collection(sorted(items, key=key, reverse=reverse))

    def take(self, count: int) -> "Collection[T]":
        return Collection(self._get_items()[:count])


class FunctionCollection(Collection):
    def by_name(self, name: str) -> Optional[T]:
        for func in self:
            if func.name == name:
                return func
        return None

    def by_address(self, addr: int) -> Optional[T]:
        for func in self:
            if func.start <= addr < func.end:
                return func
        return None

    def large(self, min_size: int = 1000) -> "FunctionCollection":
        return FunctionCollection(
            self.filter(lambda f: f.size >= min_size)._get_items()
        )

    def named(self) -> "FunctionCollection":
        return FunctionCollection(
            self.filter(lambda f: f.name is not None)._get_items()
        )


class SymbolCollection(Collection):
    def by_name(self, name: str) -> Optional[T]:
        for sym in self:
            if sym.name == name:
                return sym
        return None

    def by_type(self, symbol_type: str) -> "SymbolCollection":
        return SymbolCollection(
            self.filter(lambda s: s.symbol_type == symbol_type)._get_items()
        )

    @property
    def functions(self) -> "SymbolCollection":
        return self.by_type("function")

    @property
    def imports(self) -> "SymbolCollection":
        return self.by_type("import")


class XRefCollection(Collection):
    def from_addr(self, addr: int) -> "XRefCollection":
        return XRefCollection(self.filter(lambda x: x.from_addr == addr)._get_items())

    def to_addr(self, addr: int) -> "XRefCollection":
        return XRefCollection(self.filter(lambda x: x.to_addr == addr)._get_items())

    def by_type(self, xref_type: str) -> "XRefCollection":
        return XRefCollection(
            self.filter(lambda x: x.xref_type == xref_type)._get_items()
        )

    @property
    def calls(self) -> "XRefCollection":
        return self.by_type("call")

    @property
    def data_refs(self) -> "XRefCollection":
        return XRefCollection(
            self.filter(lambda x: x.xref_type.startswith("data"))._get_items()
        )


class InstructionCollection(Collection):
    def by_address(self, addr: int) -> Optional[T]:
        for instr in self:
            if instr.address == addr:
                return instr
        return None

    def by_mnemonic(self, mnemonic: str) -> "InstructionCollection":
        return InstructionCollection(
            self.filter(lambda i: i.mnemonic == mnemonic)._get_items()
        )

    def at_level(self, level: str) -> "InstructionCollection":
        return InstructionCollection(
            self.filter(lambda i: i.level == level)._get_items()
        )


class VariableCollection(Collection):
    def by_name(self, name: str) -> Optional[T]:
        for var in self:
            if var.name == name:
                return var
        return None

    def by_type(self, var_type: str) -> "VariableCollection":
        return VariableCollection(
            self.filter(lambda v: v.var_type == var_type)._get_items()
        )

    def in_scope(self, scope: int) -> "VariableCollection":
        return VariableCollection(self.filter(lambda v: v.scope == scope)._get_items())

    @property
    def locals(self) -> "VariableCollection":
        return VariableCollection(
            self.filter(lambda v: v.scope is not None)._get_items()
        )

    @property
    def globals(self) -> "VariableCollection":
        return VariableCollection(self.filter(lambda v: v.scope is None)._get_items())


def sum_attr(collection: Collection[T], attr: str) -> float:
    return sum(
        getattr(item, attr, 0)
        for item in collection
        if getattr(item, attr, None) is not None
    )


def avg_attr(collection: Collection[T], attr: str) -> float:
    values = [
        getattr(item, attr, 0)
        for item in collection
        if getattr(item, attr, None) is not None
    ]
    return sum(values) / len(values) if values else 0


def max_attr(collection: Collection[T], attr: str) -> Any:
    values = [
        getattr(item, attr, 0)
        for item in collection
        if getattr(item, attr, None) is not None
    ]
    return max(values) if values else None


def to_csv(collection: Collection[T]) -> str:
    items = collection.all()
    if not items or not hasattr(items[0], "to_dict"):
        return ""

    columns = list(items[0].to_dict().keys())
    lines = [",".join(columns)]
    for item in items:
        data = item.to_dict()
        lines.append(",".join(str(data.get(col, "")) for col in columns))
    return "\n".join(lines)
