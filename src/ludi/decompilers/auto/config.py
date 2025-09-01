from typing import Optional

from ..base.config import ConfigProvider


class AutoConfigProvider(ConfigProvider):
    @property
    def backend_name(self) -> str:
        return "auto"

    def auto_discover(self) -> Optional[str]:
        return None

    def validate(self, path: Optional[str] = None) -> bool:
        return True
