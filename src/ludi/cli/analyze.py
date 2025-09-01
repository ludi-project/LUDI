import inspect

from .. import ludi
from ..decompilers.base.managers import BinaryManager, FunctionManager, SymbolManager, XRefManager


class AnalyzeCLI:
    def __init__(self):
        self.analyzer = None
        self.manager_classes = self._discover_managers()

    def _discover_managers(self):
        import inspect

        from ..ludi import LUDI, SUPPORTED_BACKENDS

        manager_classes = {}

        for name, prop in inspect.getmembers(LUDI, lambda x: isinstance(x, property)):
            if prop.__doc__ and (
                "manager" in prop.__doc__.lower() or "access" in prop.__doc__.lower()
            ):
                if hasattr(prop.fget, "__annotations__") and "return" in prop.fget.__annotations__:
                    manager_class = prop.fget.__annotations__["return"]
                    manager_classes[name] = manager_class

        for _backend_name, backend_class in SUPPORTED_BACKENDS.items():
            try:
                for name, _prop in inspect.getmembers(
                    backend_class, lambda x: isinstance(x, property)
                ):
                    if name not in manager_classes and name not in ["native"]:
                        manager_classes[name] = None

                backend_methods = [name for name in dir(backend_class) if not name.startswith("_")]
                backend_manager_attrs = [
                    name for name in backend_methods if name.endswith("_manager")
                ]

                for attr_name in backend_manager_attrs:
                    manager_name = attr_name.replace("_manager", "")
                    if manager_name not in manager_classes:
                        try:
                            attr = getattr(backend_class, attr_name, None)
                            if attr and hasattr(attr, "__annotations__"):
                                manager_classes[manager_name] = attr.__annotations__.get("return")
                        except AttributeError:
                            pass

            except Exception:
                continue

        if not manager_classes:
            manager_classes = {
                "functions": FunctionManager,
                "symbols": SymbolManager,
                "xrefs": XRefManager,
                "binary": BinaryManager,
            }

        manager_classes = {k: v for k, v in manager_classes.items() if v is not None}

        return manager_classes

    def get_runtime_methods(self, manager_name, backend=None):
        if not self.analyzer:
            if manager_name in self.manager_classes:
                base_class = self.manager_classes[manager_name]
                return [
                    name
                    for name in dir(base_class)
                    if not name.startswith("_") and callable(getattr(base_class, name, None))
                ]
            return []

        try:
            manager = getattr(self.analyzer, manager_name)
            methods = [
                name
                for name in dir(manager)
                if not name.startswith("_") and callable(getattr(manager, name))
            ]
            return methods
        except AttributeError:
            return []

    def init_analyzer(self, binary_path, backend=None):
        if not self.analyzer:
            if backend:
                self.analyzer = ludi.LUDI(backend, binary_path)
            else:
                self.analyzer = ludi.LUDI("auto", binary_path)

    def handle_command(self, args):
        backend = getattr(args, "backend", None)
        self.init_analyzer(args.binary, backend)

        manager_name = args.analyze_command
        manager = getattr(self.analyzer, manager_name)

        method_name = getattr(args, f"{manager_name}_action", None)
        if not method_name:
            self._show_manager_methods(manager, manager_name)
            return

        method = getattr(manager, method_name)

        method_args = self._extract_method_args(method, args)

        result = method(**method_args)

        self._display_result(result, method_name)

    def _extract_method_args(self, method, args):
        sig = inspect.signature(method)
        method_args = {}

        for param_name in sig.parameters:
            if param_name == "self":
                continue
            if hasattr(args, param_name):
                value = getattr(args, param_name)
                if value is not None:
                    method_args[param_name] = value

        return method_args

    def _display_result(self, result, method_name):
        if result is None:
            print("None")
        elif isinstance(result, (list, tuple)):
            if not result:
                print("[]")
            else:
                for item in result:
                    self._display_item(item)
        else:
            self._display_item(result)

    def _display_item(self, item):
        if hasattr(item, "name") and hasattr(item, "start"):
            print(f"{item.name or 'unnamed'} @ 0x{item.start:x}")
        elif hasattr(item, "name") and hasattr(item, "address"):
            print(f"{item.name} @ 0x{item.address:x}")
        elif hasattr(item, "from_addr") and hasattr(item, "to_addr"):
            print(f"0x{item.from_addr:x} -> 0x{item.to_addr:x} ({item.xref_type})")
        elif isinstance(item, dict):
            formatted = ", ".join(f"{k}: {v}" for k, v in item.items())
            print(f"{{{formatted}}}")
        else:
            print(str(item))

    def _show_manager_methods(self, manager, manager_name):
        print(f"Available {manager_name} methods:")

        base_class = self.manager_classes[manager_name]
        methods = []

        for name in dir(base_class):
            if not name.startswith("_") and name not in [
                "functions",
                "symbols",
                "xrefs",
                "variables",
            ]:
                attr = getattr(base_class, name)
                if callable(attr) and hasattr(attr, "__isabstractmethod__"):
                    methods.append(name)

        for name in dir(manager):
            if (
                not name.startswith("_")
                and name not in ["functions", "symbols", "xrefs", "variables"]
                and callable(getattr(manager, name))
                and name not in methods
            ):
                methods.append(name)

        methods.sort()
        for method_name in methods:
            try:
                method_obj = getattr(manager, method_name)
                sig = inspect.signature(method_obj)
                params = []
                for param_name, param in sig.parameters.items():
                    if param_name == "self":
                        continue
                    if param.default == inspect.Parameter.empty:
                        params.append(param_name)
                    else:
                        params.append(f"{param_name}={param.default}")
                param_str = ", ".join(params) if params else ""
                print(f"  {method_name}({param_str})")
            except (AttributeError, TypeError):
                print(f"  {method_name}(...)")

    def _add_method_parsers(self, subparsers, manager_name, manager_class):
        methods = []
        for name in dir(manager_class):
            if not name.startswith("_") and name not in [
                "functions",
                "symbols",
                "xrefs",
                "variables",
            ]:
                attr = getattr(manager_class, name)
                if callable(attr):
                    methods.append((name, attr))

        for method_name, method in methods:
            try:
                sig = inspect.signature(method)
                parser = subparsers.add_parser(method_name, help=f"{method.__doc__ or method_name}")

                for param_name, param in sig.parameters.items():
                    if param_name == "self":
                        continue

                    if param.annotation == int or "addr" in param_name.lower():
                        parser.add_argument(
                            param_name,
                            type=lambda x: int(x, 16) if x.startswith("0x") else int(x),
                            help=f"{param_name} (address)",
                        )
                    elif param.default == inspect.Parameter.empty:
                        parser.add_argument(param_name, help=param_name)
                    else:
                        parser.add_argument(
                            f"--{param_name}", default=param.default, help=param_name
                        )
            except Exception:
                continue

    def add_parsers(self, subparsers):
        for manager_name, manager_class in self.manager_classes.items():
            manager_parser = subparsers.add_parser(
                manager_name, help=f"{manager_name.title()} manager methods"
            )
            manager_sub = manager_parser.add_subparsers(
                dest=f"{manager_name}_action", help=f"{manager_name.title()} methods"
            )

            self._add_method_parsers(manager_sub, manager_name, manager_class)
