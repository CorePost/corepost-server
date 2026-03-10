import uvicorn

from corepost_server.app import create_app
from corepost_server.config import get_settings


def main() -> None:
    settings = get_settings()
    uvicorn.run(create_app(settings), host=settings.host, port=settings.port)
