#!/bin/bash
# deploy.sh - Script de déploiement

set -e  # Arrêter en cas d'erreur

echo "=== Déploiement de Journal App ==="

# Variables
APP_DIR="/opt/journal_app"
VENV_DIR="$APP_DIR/venv"
REPO_URL="https://github.com/votre-repo/journal_app.git"
BRANCH="main"

# Mise à jour du code
echo "1. Mise à jour du code source..."
cd $APP_DIR
git pull origin $BRANCH

# Activation de l'environnement virtuel
echo "2. Activation de l'environnement virtuel..."
source $VENV_DIR/bin/activate

# Installation des dépendances
echo "3. Installation des dépendances..."
pip install -r requirements.txt

# Migration de la base de données
echo "4. Migration de la base de données..."
flask db upgrade

# Collecte des fichiers statiques
echo "5. Collecte des fichiers statiques..."
# Flask ne nécessite pas de collecte, mais vous pourriez ajouter des étapes ici

# Redémarrage des services
echo "6. Redémarrage des services..."
sudo systemctl restart journal_app
sudo systemctl restart nginx

# Vérification de la santé
echo "7. Vérification de la santé de l'application..."
sleep 5
curl -f http://localhost:5000/health || echo "L'application ne répond pas!"

echo "=== Déploiement terminé ==="