# =========================================================
# Multi-stage build.
#  - Stage 1 (builder): instala dependencias en una venv.
#  - Stage 2 (runtime): copia solo lo necesario y corre como
#    usuario no-root. Imagen final más pequeña y más segura.
# =========================================================

ARG PYTHON_VERSION=3.12-slim-bookworm

# ---------- Stage 1: builder ----------
FROM python:${PYTHON_VERSION} AS builder

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

# Dependencias de sistema necesarias para compilar wheels.
RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential \
        libpq-dev \
    && rm -rf /var/lib/apt/lists/*

# Crear una venv aislada para copiar al runtime.
RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

WORKDIR /build
COPY requirements/ requirements/

# Por defecto compilamos las dependencias de producción.
# En desarrollo el override de docker-compose monta el código y reinstala dev.txt.
ARG REQUIREMENTS=requirements/prod.txt
RUN pip install --upgrade pip && pip install -r ${REQUIREMENTS}


# ---------- Stage 2: runtime ----------
FROM python:${PYTHON_VERSION} AS runtime

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PATH="/opt/venv/bin:$PATH" \
    DJANGO_SETTINGS_MODULE=config.settings.prod

# Solo libpq en runtime (no toolchain de compilación).
# nmap se usa desde python-nmap para el port scanner.
# weasyprint necesita pango + fuentes para generar PDFs.
RUN apt-get update && apt-get install -y --no-install-recommends \
        libpq5 \
        curl \
        nmap \
        libpango-1.0-0 \
        libpangocairo-1.0-0 \
        libpangoft2-1.0-0 \
        libgdk-pixbuf-2.0-0 \
        fonts-liberation \
    && rm -rf /var/lib/apt/lists/*

# Usuario no-root: si alguien escapa del proceso, no es root del contenedor.
RUN groupadd --system app && useradd --system --gid app --home /home/app app \
    && mkdir -p /home/app /app/staticfiles /app/media \
    && chown -R app:app /home/app /app

COPY --from=builder /opt/venv /opt/venv

WORKDIR /app
COPY --chown=app:app . /app

USER app

EXPOSE 8000

# En producción usamos gunicorn. docker-compose lo sobrescribe en dev.
CMD ["gunicorn", "config.wsgi:application", \
     "--bind", "0.0.0.0:8000", \
     "--workers", "3", \
     "--timeout", "60", \
     "--access-logfile", "-", \
     "--error-logfile", "-"]
