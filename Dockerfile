# =========================================================
# Multi-stage build para desarrollo local.
#  - Stage 1 (builder): instala dependencias en una venv aislada.
#  - Stage 2 (runtime): copia la venv y el código; corre sin root.
#
# El docker-compose.yml monta el código con bind-mount y sobreescribe
# el CMD de cada servicio (runserver / celery worker / celery beat),
# por lo que los cambios en .py se reflejan sin reconstruir la imagen.
# =========================================================

ARG PYTHON_VERSION=3.12-slim-bookworm

# ---------- Stage 1: builder ----------
FROM python:${PYTHON_VERSION} AS builder

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

# Dependencias de sistema para compilar wheels (psycopg, cryptography...).
RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential \
        libpq-dev \
    && rm -rf /var/lib/apt/lists/*

RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

WORKDIR /build
COPY requirements/ requirements/

# docker-compose pasa REQUIREMENTS=requirements/dev.txt vía build args.
ARG REQUIREMENTS=requirements/dev.txt
RUN pip install --upgrade pip && pip install -r ${REQUIREMENTS}


# ---------- Stage 2: runtime ----------
FROM python:${PYTHON_VERSION} AS runtime

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PATH="/opt/venv/bin:$PATH"

# libpq: driver PostgreSQL.
# nmap: port scanner (python-nmap lo llama como binario).
# pango + fonts: WeasyPrint necesita estas libs para renderizar PDFs.
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

# Usuario no-root: principio de mínimo privilegio.
RUN groupadd --system app && useradd --system --gid app --home /home/app app \
    && mkdir -p /home/app /app/staticfiles /app/media \
    && chown -R app:app /home/app /app

COPY --from=builder /opt/venv /opt/venv

WORKDIR /app
COPY --chown=app:app . /app

USER app

EXPOSE 8000

# CMD por defecto: el servidor de desarrollo de Django.
# docker-compose sobreescribe este CMD en cada servicio.
CMD ["python", "manage.py", "runserver", "0.0.0.0:8000"]
