FROM python:3.11-slim

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    && rm -rf /var/lib/apt/lists/*

RUN curl -sS https://bootstrap.pypa.io/get-pip.py | python3

COPY src/ ./src/
COPY pyproject.toml .

RUN pip install --no-cache-dir -e .

EXPOSE 8000

CMD ["uvicorn", "tessera.api.server:app", "--host", "0.0.0.0", "--port", "8000"]