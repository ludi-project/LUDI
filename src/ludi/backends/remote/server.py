import os
import tempfile
import uuid
from typing import Any, Optional

try:
    from fastapi import FastAPI, File, Form, HTTPException, UploadFile
    from pydantic import BaseModel

    FASTAPI_AVAILABLE = True
except ImportError:
    FASTAPI_AVAILABLE = False

import ludi


class MethodCall(BaseModel):
    args: list[Any] = []
    kwargs: dict[str, Any] = {}


class LudiServer:
    def __init__(self):
        if not FASTAPI_AVAILABLE:
            raise RuntimeError(
                "FastAPI not available. Install with: pip install fastapi uvicorn"
            )

        self.app = FastAPI(title="LUDI Server", version="1.0.0")
        self.sessions: dict[str, Any] = {}
        self.temp_files: dict[str, str] = {}  # session_id -> temp file path

        self._setup_routes()

    def _setup_routes(self):
        @self.app.post("/sessions")
        async def create_session(
            binary: UploadFile = File(...), backend: Optional[str] = Form(None)
        ):
            session_id = str(uuid.uuid4())

            temp_file = tempfile.NamedTemporaryFile(
                delete=False, suffix=f"_{binary.filename}"
            )
            content = await binary.read()
            temp_file.write(content)
            temp_file.close()

            try:
                if backend:
                    analyzer = ludi.analyze(temp_file.name, backend=backend)
                else:
                    analyzer = ludi.analyze(temp_file.name)

                self.sessions[session_id] = analyzer
                self.temp_files[session_id] = temp_file.name

                return {
                    "session_id": session_id,
                    "backend": analyzer.backend_name,
                    "binary": binary.filename,
                }

            except Exception as e:
                os.unlink(temp_file.name)
                raise HTTPException(status_code=400, detail=str(e)) from e

        @self.app.delete("/sessions/{session_id}")
        async def close_session(session_id: str):
            if session_id in self.sessions:
                analyzer = self.sessions[session_id]
                if hasattr(analyzer, "close"):
                    analyzer.close()
                del self.sessions[session_id]

                if session_id in self.temp_files:
                    try:
                        os.unlink(self.temp_files[session_id])
                    except OSError:
                        pass
                    del self.temp_files[session_id]

                return {"status": "closed"}
            else:
                raise HTTPException(status_code=404, detail="Session not found")

        @self.app.get("/sessions")
        async def list_sessions():
            return {
                session_id: {
                    "backend": analyzer.backend_name,
                    "binary_path": analyzer.binary_path,
                }
                for session_id, analyzer in self.sessions.items()
            }

        @self.app.post("/sessions/{session_id}/{manager}/{method}")
        async def call_method(
            session_id: str, manager: str, method: str, call: MethodCall
        ):
            if session_id not in self.sessions:
                raise HTTPException(status_code=404, detail="Session not found")

            analyzer = self.sessions[session_id]

            if not hasattr(analyzer, manager):
                raise HTTPException(
                    status_code=400, detail=f"Unknown manager: {manager}"
                )

            manager_obj = getattr(analyzer, manager)

            if not hasattr(manager_obj, method):
                raise HTTPException(status_code=400, detail=f"Unknown method: {method}")

            method_obj = getattr(manager_obj, method)
            if not callable(method_obj):
                raise HTTPException(status_code=400, detail=f"Not a method: {method}")

            try:
                result = method_obj(*call.args, **call.kwargs)

                serialized_result = self._serialize_result(result)

                return {"result": serialized_result}

            except Exception as e:
                return {"error": str(e)}

        @self.app.get("/backends")
        async def list_backends():
            from ludi.decompilers.base.config import get_config_manager

            config_manager = get_config_manager()
            config_manager.load_config()

            return {
                "local": config_manager.get_available_local_backends(),
                "remote": [
                    name
                    for name, config in config_manager.list_backends().items()
                    if config == "remote"
                ],
            }

    def _serialize_result(self, result):
        if result is None:
            return None
        elif isinstance(result, (str, int, float, bool)):
            return result
        elif isinstance(result, (list, tuple)):
            return [self._serialize_result(item) for item in result]
        elif isinstance(result, dict):
            return {k: self._serialize_result(v) for k, v in result.items()}
        elif hasattr(result, "__dict__"):
            return {k: self._serialize_result(v) for k, v in result.__dict__.items()}
        else:
            return str(result)


def create_server() -> LudiServer:
    return LudiServer()


def run_server(host: str = "0.0.0.0", port: int = 8080):
    try:
        import uvicorn
    except ImportError as e:
        raise RuntimeError(
            "uvicorn not available. Install with: pip install uvicorn"
        ) from e

    server = create_server()
    print(f"Starting LUDI server on {host}:{port}")
    uvicorn.run(server.app, host=host, port=port)
