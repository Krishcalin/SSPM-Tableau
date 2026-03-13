FROM python:3.12.10-slim@sha256:85824326bc4ae27a1abb04e20ed9255087df38ed3397e9e871832ad120a788e0 AS base

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

HEALTHCHECK --interval=60s --timeout=5s --start-period=5s --retries=1 \
    CMD ["python", "-c", "import tableau_sspm; print('ok')"]

ENTRYPOINT ["tableau-sspm"]
CMD ["--output-dir", "/app/output"]
