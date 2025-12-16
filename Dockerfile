# Dockerfile
FROM python:3.11-slim

# Installation des dépendances système
RUN apt-get update && apt-get install -y \
    gcc \
    libpq-dev \
    && rm -rf /var/lib/apt/lists/*

# Création de l'utilisateur non-root
RUN useradd --create-home appuser
WORKDIR /home/appuser/app
USER appuser

# Copie des fichiers de dépendances
COPY --chown=appuser:appuser requirements.txt .

# Installation des dépendances Python
RUN pip install --no-cache-dir -r requirements.txt

# Copie du code de l'application
COPY --chown=appuser:appuser . .

# Variables d'environnement
ENV FLASK_APP=app.py
ENV FLASK_ENV=production
ENV PYTHONUNBUFFERED=1
ENV PYTHONPATH=/home/appuser/app

# Exposition du port
EXPOSE 5000

# Commande de démarrage
CMD ["gunicorn", "--config", "gunicorn_config.py", "app:app"]