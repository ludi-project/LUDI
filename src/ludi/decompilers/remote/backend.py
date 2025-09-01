from typing import Optional

from ..base.decompiler import DecompilerBase
from .client import LudiClient
from .managers import (
    RemoteBinaryManager,
    RemoteFunctionManager,
    RemoteSymbolManager,
    RemoteXRefManager,
)


class RemoteBackend(DecompilerBase):
    def __init__(self, binary_path: str, server_config: dict, target_backend: Optional[str] = None):
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

        self.backend_name = f"remote({target_backend or 'auto'})"

    def close(self):
        if hasattr(self, "client"):
            self.client.close_session()

    def __del__(self):
        self.close()
