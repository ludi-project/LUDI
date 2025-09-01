from typing import Any, Optional

import requests


class LudiClient:
    def __init__(self, base_url: str, auth: Optional[dict[str, str]] = None):
        self.base_url = base_url.rstrip("/")
        self.session = requests.Session()

        if auth:
            if "token" in auth:
                self.session.headers.update(
                    {"Authorization": f'Bearer {auth["token"]}'}
                )
            elif "user" in auth and "pass" in auth:
                self.session.auth = (auth["user"], auth["pass"])

        self.session_id: Optional[str] = None

    def create_session(self, binary_path: str, backend: Optional[str] = None) -> str:
        with open(binary_path, "rb") as f:
            files = {"binary": f}
            data = {"backend": backend} if backend else {}

            response = self.session.post(
                f"{self.base_url}/sessions", files=files, data=data
            )
            response.raise_for_status()

            result = response.json()
            self.session_id = result["session_id"]
            return self.session_id

    def close_session(self):
        if self.session_id:
            try:
                self.session.delete(f"{self.base_url}/sessions/{self.session_id}")
            except Exception:
                pass  # Best effort cleanup
            finally:
                self.session_id = None

    def call_method(self, manager: str, method: str, *args, **kwargs) -> Any:
        if not self.session_id:
            raise RuntimeError("No active session")

        url = f"{self.base_url}/sessions/{self.session_id}/{manager}/{method}"
        payload = {"args": args, "kwargs": kwargs}

        response = self.session.post(url, json=payload)
        response.raise_for_status()

        result = response.json()
        if result.get("error"):
            raise Exception(result["error"])

        return result.get("result")

    def __del__(self):
        self.close_session()
