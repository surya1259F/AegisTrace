import os
import sys
from pathlib import Path

# Ensure application root directory is available in sys.path
if getattr(sys, "frozen", False):
    root_dir = Path(sys._MEIPASS)
else:
    root_dir = Path(__file__).resolve().parent.parent

if str(root_dir) not in sys.path:
    sys.path.insert(0, str(root_dir))

import uvicorn
from backend.app.main import app
from backend.app.core.config import get_backend_port

def main():
    port = get_backend_port()
    is_frozen = getattr(sys, "frozen", False)
    if is_frozen:
        uvicorn.run(app, host="127.0.0.1", port=port, reload=False, log_level="info")
    else:
        uvicorn.run("backend.app.main:app", host="127.0.0.1", port=port, reload=True)

if __name__ == "__main__":
    main()

