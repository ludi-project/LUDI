import inspect

# Import will be done lazily to avoid circular import


class AnalyzeCLI:
    def __init__(self):
        self.backend = None
        self.manager_classes = self._discover_managers()

    def _discover_managers(self):
        import inspect

        from ..core.ludi import SUPPORTED_BACKENDS
        from ..backends.base.decompiler import DecompilerBase

        manager_classes = {}

        # Discover managers from the base decompiler class
        for name, prop in inspect.getmembers(
            DecompilerBase, lambda x: isinstance(x, property)
        ):
            if (
                hasattr(prop.fget, "__annotations__")
                and "return" in prop.fget.__annotations__
            ):
                manager_class = prop.fget.__annotations__["return"]
                manager_classes[name] = manager_class

        for _backend_name, backend_class in SUPPORTED_BACKENDS.items():
            try:
                for name, _prop in inspect.getmembers(
                    backend_class, lambda x: isinstance(x, property)
                ):
                    if name not in manager_classes and name not in ["native"]:
                        manager_classes[name] = None

                backend_methods = [
                    name for name in dir(backend_class) if not name.startswith("_")
                ]
                backend_manager_attrs = [
                    name for name in backend_methods if name.endswith("_manager")
                ]

                for attr_name in backend_manager_attrs:
                    manager_name = attr_name.replace("_manager", "")
                    if manager_name not in manager_classes:
                        try:
                            attr = getattr(backend_class, attr_name, None)
                            if attr and hasattr(attr, "__annotations__"):
                                manager_classes[
                                    manager_name
                                ] = attr.__annotations__.get("return")
                        except AttributeError:
                            pass

            except Exception:
                continue

        # Import actual manager classes to replace string annotations
        try:
            from ..backends.base.managers import (
                FunctionManager,
                SymbolManager,
                XRefManager,
                BinaryManager,
                TypeManager,
                MemoryManager,
                ArchitectureManager,
            )

            # Replace string annotations with actual classes
            class_mapping = {
                "FunctionManager": FunctionManager,
                "SymbolManager": SymbolManager,
                "XRefManager": XRefManager,
                "BinaryManager": BinaryManager,
                "TypeManager": TypeManager,
                "MemoryManager": MemoryManager,
                "ArchitectureManager": ArchitectureManager,
            }

            for name, cls in manager_classes.items():
                if isinstance(cls, str) and cls in class_mapping:
                    manager_classes[name] = class_mapping[cls]

        except ImportError:
            pass

        if not manager_classes:
            manager_classes = {
                "functions": FunctionManager,
                "symbols": SymbolManager,
                "xrefs": XRefManager,
                "binary": BinaryManager,
            }

        manager_classes = {k: v for k, v in manager_classes.items() if v is not None}

        return manager_classes

    def get_runtime_methods(self, manager_name, backend_config=None):
        if not self.backend:
            if manager_name in self.manager_classes:
                base_class = self.manager_classes[manager_name]
                return [
                    name
                    for name in dir(base_class)
                    if not name.startswith("_")
                    and callable(getattr(base_class, name, None))
                ]
            return []

        try:
            manager = getattr(self.backend, manager_name)
            methods = [
                name
                for name in dir(manager)
                if not name.startswith("_") and callable(getattr(manager, name))
            ]
            return methods
        except AttributeError:
            return []

    def init_backend(self, binary_path, backend_config=None):
        if not self.backend:
            from .. import analyze

            if backend_config:
                self.backend = analyze(binary_path, backend=backend_config)
            else:
                self.backend = analyze(binary_path)

    def handle_command(self, args):
        backend_config = getattr(args, "backend", None)
        self.init_backend(args.binary, backend_config)

        manager_name = args.analyze_command
        manager = getattr(self.backend, manager_name)

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
        from ..core.utils import display_result

        display_result(result)

    def _show_manager_methods(self, manager, manager_name):
        print(f"Available {manager_name} methods:")

        base_class = self.manager_classes[manager_name]
        methods = []

        # Get manager property names to exclude (dynamic discovery)
        excluded_names = set(self.manager_classes.keys())
        excluded_names.add("variables")  # Legacy exclusion

        for name in dir(base_class):
            if not name.startswith("_") and name not in excluded_names:
                attr = getattr(base_class, name)
                if callable(attr) and hasattr(attr, "__isabstractmethod__"):
                    methods.append(name)

        for name in dir(manager):
            if (
                not name.startswith("_")
                and name not in excluded_names
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
        # Get manager property names to exclude (dynamic discovery)
        excluded_names = set(self.manager_classes.keys())
        excluded_names.add("variables")  # Legacy exclusion

        methods = []
        for name in dir(manager_class):
            if not name.startswith("_") and name not in excluded_names:
                attr = getattr(manager_class, name)
                if callable(attr) and hasattr(attr, "__isabstractmethod__"):
                    methods.append((name, attr))

        for method_name, method in methods:
            try:
                sig = inspect.signature(method)
                parser = subparsers.add_parser(
                    method_name, help=f"{method.__doc__ or method_name}"
                )

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
