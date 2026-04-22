# =========================================================
# Multi-stage build.
#  Stage 1 (builder): instala dependencias Python en venv aislada.
#  Stage 2 (runtime): copia venv, instala binarios del sistema
#                     (nmap, nuclei, playwright-chromium) y corre
#                     sin root.
# =========================================================

ARG PYTHON_VERSION=3.12-slim-bookworm

# ─────────────────────────── Stage 1: builder ──────────────────────────────
FROM python:${PYTHON_VERSION} AS builder

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential \
        libpq-dev \
    && rm -rf /var/lib/apt/lists/*

RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

WORKDIR /build
COPY requirements/ requirements/

ARG REQUIREMENTS=requirements/dev.txt
RUN pip install --upgrade pip && pip install -r ${REQUIREMENTS}

# ─────────────────────────── Stage 2: runtime ──────────────────────────────
FROM python:${PYTHON_VERSION} AS runtime

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PATH="/opt/venv/bin:$PATH" \
    # Playwright: guardar browsers en path fijo accesible por usuario app
    PLAYWRIGHT_BROWSERS_PATH=/opt/playwright-browsers \
    # Nuclei: templates path y home
    NUCLEI_TEMPLATES_PATH=/opt/nuclei-templates

# ── Sistema: runtime libs ──────────────────────────────────────────────────
RUN apt-get update && apt-get install -y --no-install-recommends \
        # PostgreSQL client
        libpq5 \
        # Utilidades
        curl \
        unzip \
        # Port scanning
        nmap \
        # WeasyPrint (PDF)
        libpango-1.0-0 \
        libpangocairo-1.0-0 \
        libpangoft2-1.0-0 \
        libgdk-pixbuf-2.0-0 \
        fonts-liberation \
        # Playwright / Chromium system deps
        libnss3 \
        libnspr4 \
        libdbus-1-3 \
        libatk1.0-0 \
        libatk-bridge2.0-0 \
        libcups2 \
        libdrm2 \
        libxkbcommon0 \
        libatspi2.0-0 \
        libx11-6 \
        libxcomposite1 \
        libxdamage1 \
        libxext6 \
        libxfixes3 \
        libxrandr2 \
        libgbm1 \
        libpango-1.0-0 \
        libasound2 \
    && rm -rf /var/lib/apt/lists/*

# ── Nuclei (vulnerability scanner) ────────────────────────────────────────
# Descarga el binario oficial de ProjectDiscovery. Usamos ARG para poder
# actualizar la versión fácilmente sin tocar el resto del Dockerfile.
ARG NUCLEI_VERSION=3.3.2
RUN curl -sL \
    "https://github.com/projectdiscovery/nuclei/releases/download/v${NUCLEI_VERSION}/nuclei_${NUCLEI_VERSION}_linux_amd64.zip" \
    -o /tmp/nuclei.zip \
    && unzip -q /tmp/nuclei.zip -d /tmp/nuclei_bin \
    && mv /tmp/nuclei_bin/nuclei /usr/local/bin/nuclei \
    && chmod +x /usr/local/bin/nuclei \
    && rm -rf /tmp/nuclei.zip /tmp/nuclei_bin \
    # Directorio de templates (se rellenan en primer uso con nuclei -update-templates)
    && mkdir -p /opt/nuclei-templates

# ── Python venv ────────────────────────────────────────────────────────────
COPY --from=builder /opt/venv /opt/venv

# ── Playwright: instalar Chromium (usa PATH del venv ya copiado) ───────────
RUN playwright install chromium \
    && mkdir -p /opt/playwright-browsers

# ── Usuario no-root ────────────────────────────────────────────────────────
RUN groupadd --system app && useradd --system --gid app --home /home/app app \
    && mkdir -p /home/app /app/staticfiles /app/media /app/.nuclei-cache \
    && chown -R app:app /home/app /app /opt/playwright-browsers /opt/nuclei-templates

COPY --chown=app:app . /app

WORKDIR /app
USER app

EXPOSE 8000

# Dev: Django runserver (Channels lo convierte en ASGI automáticamente)
CMD ["python", "manage.py", "runserver", "0.0.0.0:8000"]
