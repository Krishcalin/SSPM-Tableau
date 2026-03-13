FROM python:3.12-slim AS base

LABEL maintainer="Security Engineering"
LABEL description="Tableau Cloud SSPM Scanner"

RUN groupadd -r sspm && useradd -r -g sspm -d /app -s /sbin/nologin sspm

WORKDIR /app

COPY pyproject.toml requirements.txt ./
COPY src/ src/

RUN pip install --no-cache-dir -e . && \
    rm -rf /root/.cache

RUN mkdir -p /app/output && chown sspm:sspm /app/output

USER sspm

ENTRYPOINT ["tableau-sspm"]
CMD ["--output-dir", "/app/output"]
