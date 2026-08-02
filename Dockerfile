FROM python:3.12-slim
ARG APP_VERSION=1.0.0
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PANTRY_DATA_DIR=/data APP_VERSION=${APP_VERSION}
LABEL org.opencontainers.image.title="Shelf Life" \
      org.opencontainers.image.version="${APP_VERSION}" \
      org.opencontainers.image.source="https://github.com/xyciasav/pantry_app"
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY app ./app
RUN mkdir -p /data
EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --retries=3 CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/health')"
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
