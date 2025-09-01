from typing import Any, Optional

from ..base.decompiler import DecompilerBase

try:
    from .client import LudiClient
    from .managers import (
        RemoteBinaryManager,
        RemoteFunctionManager,
        RemoteSymbolManager,
        RemoteXRefManager,
        RemoteTypeManager,
        RemoteArchitectureManager,
        RemoteMemoryManager,
    )

    REMOTE_AVAILABLE = True
except ImportError:
    REMOTE_AVAILABLE = False


class Remote(DecompilerBase):
    def __init__(
        self,
        binary_path: str,
        server_config: dict,
        target_backend: Optional[str] = None,
    ):
        if not REMOTE_AVAILABLE:
            raise RuntimeError(
                "Remote backend requires 'requests' package. Install with: pip install requests"
            )

        super().__init__(binary_path)

        protocol = server_config.get("protocol", "http")
        server = server_config["server"]
        port = server_config.get("port", 80 if protocol == "http" else 443)

        base_url = f"{protocol}://{server}:{port}"
        auth = server_config.get("auth", {})

        self.client = LudiClient(base_url, auth)
        self.session_id = self.client.create_session(binary_path, target_backend)

        self.functions = RemoteFunctionManager(self.client)
        self.symbols = RemoteSymbolManager(self.client)
        self.xrefs = RemoteXRefManager(self.client)
        self.binary = RemoteBinaryManager(self.client)
        self.types = RemoteTypeManager(self.client)
        self.architecture = RemoteArchitectureManager(self.client)
        self.memory = RemoteMemoryManager(self.client)

        self.backend_name = f"remote({target_backend or 'auto'})"

    def close(self):
        if hasattr(self, "client"):
            self.client.close_session()

    def __del__(self):
        self.close()

    @staticmethod
    def get_backend_name() -> str:
        return "remote"

    @staticmethod
    def auto_discover(**kwargs) -> tuple[bool, dict[str, Any]]:
        # Cannot auto-discover remote servers
        return False, {}

    @staticmethod
    def validate(config) -> bool:
        if config is None:
            return False

        server = (
            config.get("server")
            if isinstance(config, dict)
            else getattr(config, "server", None)
        )

        # Remote backend validation would require network connectivity check
        # For now, just check if we have basic config
        return REMOTE_AVAILABLE and server is not None

    @staticmethod
    def get_default_config() -> dict:
        """Generate default configuration for remote backend."""
        # Remote backend requires manual configuration
        return {
            "type": "remote",
            "autodiscover": False,  # Can't autodiscover remote servers
            "enabled": False,  # Disabled by default until configured
            "server": "localhost",  # Example server
            "port": 8080,
            "protocol": "http",
            "auth": {
                "type": "none",  # Options: none, token, basic
            },
            "options": {
                "timeout": 300,  # 5 minute timeout for remote operations
                "target_backend": None,  # Optional: specify which backend the server should use
            },
        }
