FROM python:3.13-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    TOLLGATE_DB=/data/tollgate.db \
    PORT=8000

# Run as an unprivileged user; /data holds the SQLite file.
RUN useradd --create-home --uid 10001 tollgate && mkdir /data && chown tollgate /data

WORKDIR /app
COPY pyproject.toml README.md LICENSE ./
COPY src ./src
RUN pip install .

USER tollgate
EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s \
  CMD python -c "import os,urllib.request as u; u.urlopen('http://127.0.0.1:%s/api/health' % os.environ.get('PORT','8000'), timeout=4)"

CMD ["sh", "-c", "exec tollgate serve --host 0.0.0.0 --port ${PORT}"]
