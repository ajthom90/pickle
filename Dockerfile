FROM python:3.12-slim-bookworm

RUN apt-get update \
 && apt-get install -y --no-install-recommends wireguard-tools wireguard-go iproute2 iputils-ping \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY app/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY app/pickle_wan ./pickle_wan

ENV PICKLE_CONFIG=/config/config.yaml \
    PICKLE_DB=/data/pickle.db \
    PYTHONUNBUFFERED=1
VOLUME ["/data"]
EXPOSE 8080

HEALTHCHECK --interval=60s --timeout=5s CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8080/api/status', timeout=4)" || exit 1

CMD ["uvicorn", "pickle_wan.main:app", "--host", "0.0.0.0", "--port", "8080"]
