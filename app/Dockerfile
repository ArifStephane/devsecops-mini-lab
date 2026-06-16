# =============================================================================
# Dockerfile — application cible du mini-lab DevSecOps
# Image de production : multi-stage, non-root, minimale
# =============================================================================

# ---- Étape 1 : builder ----
FROM python:3.12-slim AS builder

WORKDIR /build

# Copie et installation des dépendances dans un répertoire isolé
COPY requirements.txt .
RUN pip install --no-cache-dir --prefix=/install -r requirements.txt


# ---- Étape 2 : image finale ----
FROM python:3.12-slim AS final

# Métadonnées OCI standard (nécessaires pour le SBOM)
LABEL org.opencontainers.image.title="target-api"
LABEL org.opencontainers.image.description="Application cible mini-lab DevSecOps"
LABEL org.opencontainers.image.version="1.0.0"
LABEL org.opencontainers.image.source="https://github.com/ArifStephane/devsecops-mini-lab"

# Création d'un utilisateur non-root
RUN groupadd --gid 1001 appgroup && \
    useradd --uid 1001 --gid appgroup --no-create-home appuser

WORKDIR /app

# Copie des dépendances compilées depuis le builder
COPY --from=builder /install /usr/local

# Copie du code applicatif
COPY main.py .

# Passage à l'utilisateur non-root
USER appuser

# Port d'écoute
EXPOSE 8000

# Healthcheck intégré à l'image
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8000/health')"

# Point d'entrée
ENTRYPOINT ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
