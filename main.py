from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parent
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from corepost_server.app import create_app
from corepost_server.config import get_settings

import uvicorn


if __name__ == "__main__":
    settings = get_settings()
    uvicorn.run(create_app(settings), host=settings.host, port=settings.port, log_level=settings.log_level.lower())
