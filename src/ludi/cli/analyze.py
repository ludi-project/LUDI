"""Smart analysis CLI that dynamically reads manager methods."""

import ludi
import inspect
from ..decompilers.base.managers import FunctionManager, SymbolManager, XRefManager, BinaryManager


class AnalyzeCLI:
    """CLI that dynamically exposes all manager methods."""
    
    def __init__(self):
        self.analyzer = None
        self.manager_classes = self._discover_managers()
    
    def _discover_managers(self):
        """Automatically discover manager classes from all supported backends."""
        import inspect
        from ..ludi import LUDI, SUPPORTED_BACKENDS
        
        manager_classes = {}
        
        # First get base managers from LUDI class
        for name, prop in inspect.getmembers(LUDI, lambda x: isinstance(x, property)):
            if prop.__doc__ and ('manager' in prop.__doc__.lower() or 'access' in prop.__doc__.lower()):
                if hasattr(prop.fget, '__annotations__') and 'return' in prop.fget.__annotations__:
                    manager_class = prop.fget.__annotations__['return']
                    manager_classes[name] = manager_class
        
        # Try to discover backend-specific managers from all supported backends
        for backend_name, backend_class in SUPPORTED_BACKENDS.items():
            try:
                # Get all manager properties from this backend
                for name, prop in inspect.getmembers(backend_class, lambda x: isinstance(x, property)):
                    if name not in manager_classes and name not in ['native']:
                        # This is a potential manager not in the base LUDI class
                        manager_classes[name] = None  # We'll resolve this later
                        
                # Also check for any methods that might indicate additional functionality
                backend_methods = [name for name in dir(backend_class) if not name.startswith('_')]
                backend_manager_attrs = [name for name in backend_methods if name.endswith('_manager')]
                
                for attr_name in backend_manager_attrs:
                    manager_name = attr_name.replace('_manager', '')
                    if manager_name not in manager_classes:
                        # Try to get the manager class from the attribute
                        try:
                            attr = getattr(backend_class, attr_name, None)
                            if attr and hasattr(attr, '__annotations__'):
                                manager_classes[manager_name] = attr.__annotations__.get('return')
                        except:
                            pass
                            
            except Exception:
                # Skip backends that can't be inspected
                continue
        
        # Fallback to hardcoded if discovery fails completely
        if not manager_classes:
            manager_classes = {
                'functions': FunctionManager,
                'symbols': SymbolManager, 
                'xrefs': XRefManager,
                'binary': BinaryManager
            }
        
        # Remove None values (failed discoveries)
        manager_classes = {k: v for k, v in manager_classes.items() if v is not None}
        
        return manager_classes
    
    def get_runtime_methods(self, manager_name, backend=None):
        """Get methods available at runtime for a specific backend."""
        if not self.analyzer:
            # Use base class methods if no analyzer loaded
            if manager_name in self.manager_classes:
                base_class = self.manager_classes[manager_name]
                return [name for name in dir(base_class) 
                       if not name.startswith('_') and callable(getattr(base_class, name, None))]
            return []
        
        # Get actual methods from loaded analyzer's manager
        try:
            manager = getattr(self.analyzer, manager_name)
            methods = [name for name in dir(manager) 
                      if not name.startswith('_') and callable(getattr(manager, name))]
            return methods
        except AttributeError:
            return []
    
    def init_analyzer(self, binary_path, backend=None):
        """Initialize analyzer with optional backend selection."""
        if not self.analyzer:
            if backend:
                self.analyzer = ludi.LUDI(backend, binary_path)
            else:
                self.analyzer = ludi.auto(binary_path)
    
    def handle_command(self, args):
        """Route commands to manager methods."""
        backend = getattr(args, 'backend', None)
        self.init_analyzer(args.binary, backend)
        
        # Get the manager
        manager_name = args.analyze_command
        manager = getattr(self.analyzer, manager_name)
        
        # Get the method
        method_name = getattr(args, f'{manager_name}_action', None)
        if not method_name:
            # Show available methods for this manager
            self._show_manager_methods(manager, manager_name)
            return
            
        method = getattr(manager, method_name)
        
        # Get method arguments from CLI args
        method_args = self._extract_method_args(method, args)
        
        # Call the method
        result = method(**method_args)
        
        # Display result
        self._display_result(result, method_name)
    
    def _extract_method_args(self, method, args):
        """Extract method arguments from CLI args."""
        sig = inspect.signature(method)
        method_args = {}
        
        for param_name in sig.parameters:
            if param_name == 'self':
                continue
            if hasattr(args, param_name):
                value = getattr(args, param_name)
                # Handle optional parameters that are None
                if value is not None:
                    method_args[param_name] = value
        
        return method_args
    
    def _display_result(self, result, method_name):
        """Display method result."""
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
        """Display a single item."""
        if hasattr(item, 'name') and hasattr(item, 'start'):
            # Function-like object
            print(f"{item.name or 'unnamed'} @ 0x{item.start:x}")
        elif hasattr(item, 'name') and hasattr(item, 'address'):
            # Symbol-like object
            print(f"{item.name} @ 0x{item.address:x}")
        elif hasattr(item, 'from_addr') and hasattr(item, 'to_addr'):
            # XRef-like object
            print(f"0x{item.from_addr:x} -> 0x{item.to_addr:x} ({item.xref_type})")
        elif isinstance(item, dict):
            # Dict result (like segments, sections)
            formatted = ', '.join(f"{k}: {v}" for k, v in item.items())
            print(f"{{{formatted}}}")
        else:
            print(str(item))
    
    def _show_manager_methods(self, manager, manager_name):
        """Show available methods for a manager."""
        print(f"Available {manager_name} methods:")
        
        # Get methods from the base manager class to show the API
        base_class = self.manager_classes[manager_name]
        methods = []
        
        for name in dir(base_class):
            if not name.startswith('_') and name not in ['functions', 'symbols', 'xrefs', 'variables']:
                attr = getattr(base_class, name)
                if callable(attr) and hasattr(attr, '__isabstractmethod__'):
                    methods.append(name)
        
        # Also get non-abstract methods
        for name in dir(manager):
            if (not name.startswith('_') and 
                name not in ['functions', 'symbols', 'xrefs', 'variables'] and
                callable(getattr(manager, name)) and
                name not in methods):
                methods.append(name)
        
        methods.sort()
        for method_name in methods:
            try:
                method_obj = getattr(manager, method_name)
                sig = inspect.signature(method_obj)
                params = []
                for param_name, param in sig.parameters.items():
                    if param_name == 'self':
                        continue
                    if param.default == inspect.Parameter.empty:
                        params.append(param_name)
                    else:
                        params.append(f"{param_name}={param.default}")
                param_str = ', '.join(params) if params else ''
                print(f"  {method_name}({param_str})")
            except:
                print(f"  {method_name}(...)")
    
    def _add_method_parsers(self, subparsers, manager_name, manager_class):
        """Dynamically add parsers for all methods in a manager."""
        # Get all abstract methods from base class
        methods = []
        for name in dir(manager_class):
            if not name.startswith('_') and name not in ['functions', 'symbols', 'xrefs', 'variables']:
                attr = getattr(manager_class, name)
                if callable(attr):
                    methods.append((name, attr))
        
        for method_name, method in methods:
            try:
                sig = inspect.signature(method)
                parser = subparsers.add_parser(method_name, help=f"{method.__doc__ or method_name}")
                
                for param_name, param in sig.parameters.items():
                    if param_name == 'self':
                        continue
                    
                    # Determine argument type and setup
                    if param.annotation == int or 'addr' in param_name.lower():
                        parser.add_argument(
                            param_name, 
                            type=lambda x: int(x, 16) if x.startswith('0x') else int(x),
                            help=f"{param_name} (address)"
                        )
                    elif param.default == inspect.Parameter.empty:
                        # Required parameter
                        parser.add_argument(param_name, help=param_name)
                    else:
                        # Optional parameter
                        parser.add_argument(f'--{param_name}', default=param.default, help=param_name)
            except Exception as e:
                # Skip methods we can't introspect
                continue
    
    def add_parsers(self, subparsers):
        """Dynamically add analysis subcommands for all managers."""
        # Add backend selection to main analyze parser
        
        # Dynamically create parsers for each manager
        for manager_name, manager_class in self.manager_classes.items():
            manager_parser = subparsers.add_parser(manager_name, help=f'{manager_name.title()} manager methods')
            manager_sub = manager_parser.add_subparsers(dest=f'{manager_name}_action', help=f'{manager_name.title()} methods')
            
            # Add methods for this manager
            self._add_method_parsers(manager_sub, manager_name, manager_class)