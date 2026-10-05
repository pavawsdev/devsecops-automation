# syntax=docker/dockerfile:1.7
FROM python:3.12-slim AS builder
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir --prefix=/install -r requirements.txt

FROM python:3.12-slim
# Pick up Debian security fixes released after the base image was built.
RUN apt-get update \
    && apt-get upgrade -y --no-install-recommends \
    && rm -rf /var/lib/apt/lists/*
RUN useradd -r -u 10001 app
WORKDIR /app
COPY --from=builder /install /usr/local
COPY vulnauto/ ./vulnauto/
COPY soarflow/ ./soarflow/
USER 10001
ENTRYPOINT ["python", "-m", "vulnauto.cli"]
