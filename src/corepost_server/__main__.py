from __future__ import annotations

import uvicorn

from .app import create_app
from .config import get_settings


def main() -> None:
    settings = get_settings()
    uvicorn.run(create_app(settings), host=settings.host, port=settings.port, log_level=settings.log_level.lower())


if __name__ == "__main__":
    main()
