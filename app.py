from __future__ import annotations

import os
import importlib
import subprocess
import sys
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parent

if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from backend.api import app
from backend.config import FRONTEND_DIST
    
     
def _ensure_frontend_built() -> None:
    index_file = FRONTEND_DIST / "index.html"
    if index_file.exists():
        return
    
    frontend_dir = ROOT_DIR / "frontend"
    package_json = frontend_dir / "package.json"
    if not package_json.exists():
        raise RuntimeError("frontend/package.json is missing, so the UI cannot be built.")

    npm_exe = "npm.cmd" if sys.platform.startswith("win") else "npm"
    subprocess.run([npm_exe, "install"], cwd=frontend_dir, check=True)
    subprocess.run([npm_exe, "run", "build"], cwd=frontend_dir, check=True)


if __name__ == "__main__": 
    _ensure_frontend_built()
    host = os.environ.get("HOST", "127.0.0.1")
    port = int(os.environ.get("PORT", "8000"))
    uvicorn = importlib.import_module("uvicorn")
    uvicorn.run(app, host=host, port=port, reload=False)


