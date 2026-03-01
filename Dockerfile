FROM python:3.11-slim

WORKDIR /app

COPY . .

RUN pip install --no-cache-dir uv && uv sync --no-dev

ENV MCP_TRANSPORT=http
ENV MCP_PORT=8000
EXPOSE 8000

CMD ["uv", "run", "main.py"]
