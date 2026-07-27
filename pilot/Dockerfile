FROM python:3.12.3-slim-bookworm

WORKDIR /app
COPY app.py index.html /app/
RUN useradd --create-home --uid 10001 --shell /usr/sbin/nologin pilot \
    && mkdir -p /data \
    && chown -R pilot:pilot /app /data

USER 10001:10001
ENV PILOT_HOST=0.0.0.0 PILOT_PORT=8080 PILOT_DB=/data/pilot.db PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
EXPOSE 8080
HEALTHCHECK --interval=15s --timeout=3s --retries=3 CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8080/health/live', timeout=2)"
ENTRYPOINT ["python", "/app/app.py"]
