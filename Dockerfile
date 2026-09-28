FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    ULPF_HOST=0.0.0.0 \
    ULPF_PORT=8080 \
    ULPF_DB_PATH=/app/data/ulpf.db

WORKDIR /app
COPY app.py ./app.py
COPY static ./static
COPY parsers ./parsers
RUN mkdir -p /app/data

EXPOSE 8080
VOLUME ["/app/data"]
CMD ["python", "app.py"]
