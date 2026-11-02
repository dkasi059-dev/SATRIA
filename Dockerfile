FROM golang:1.24-bookworm AS tool-builder
ENV CGO_ENABLED=0
RUN go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest \
 && go install github.com/BishopFox/jsluice/cmd/jsluice@latest

FROM python:3.12-slim-bookworm
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PATH="/root/go/bin:${PATH}"
WORKDIR /app
RUN apt-get update && apt-get install -y --no-install-recommends \
    libpango-1.0-0 libpangoft2-1.0-0 libcairo2 libgdk-pixbuf-2.0-0 \
    libffi-dev libjpeg-dev libopenjp2-7-dev shared-mime-info \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*
COPY --from=tool-builder /go/bin/nuclei /usr/local/bin/nuclei
COPY --from=tool-builder /go/bin/jsluice /usr/local/bin/jsluice
COPY requirements.txt ./requirements.txt
RUN python -m pip install --upgrade pip && pip install -r requirements.txt
COPY . .
EXPOSE 8501
HEALTHCHECK --interval=30s --timeout=5s --start-period=30s --retries=3 \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8501/_stcore/health', timeout=3)" || exit 1
CMD ["streamlit", "run", "app.py", "--server.address=0.0.0.0", "--server.port=8501"]
