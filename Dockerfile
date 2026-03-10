FROM python:3.13-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

COPY pyproject.toml README.md main.py ./
COPY src ./src

RUN pip install --no-cache-dir .

VOLUME ["/data"]

EXPOSE 8000

CMD ["python", "main.py"]
