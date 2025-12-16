import os
from flask import Flask, render_template, request, redirect, url_for, flash, jsonify
from flask_login import LoginManager, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.middleware.proxy_fix import ProxyFix
from database import db, User, Journal, Comment
from config import config
from datetime import datetime
import re

# Initialisation de l'application
app = Flask(__name__)

# Configuration
config_name = os.getenv('FLASK_ENV', 'production')
app.config.from_object(config[config_name])

# Sécurité supplémentaire
if app.config.get('ENABLE_HTTPS', False):
    app.config['PREFERRED_URL_SCHEME'] = 'https'

# Pour les proxies (nécessaire quand derrière un proxy comme Nginx)
app.wsgi_app = ProxyFix(app.wsgi_app, x_proto=1, x_host=1)

# Initialisation de la base de données
db.init_app(app)

# Configuration de Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
login_manager.login_message = 'Veuillez vous connecter pour accéder à cette page.'
login_manager.login_message_category = 'info'

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Création des tables
with app.app_context():
    db.create_all()

# Fonctions utilitaires
def is_valid_email(email):
    """Valider le format de l'email"""
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return re.match(pattern, email) is not None

def is_valid_username(username):
    """Valider le nom d'utilisateur"""
    pattern = r'^[a-zA-Z0-9_-]{3,20}$'
    return re.match(pattern, username) is not None

def is_strong_password(password):
    """Vérifier la force du mot de passe"""
    if len(password) < 8:
        return False, "Le mot de passe doit contenir au moins 8 caractères"
    
    if not any(c.isupper() for c in password):
        return False, "Le mot de passe doit contenir au moins une majuscule"
    
    if not any(c.islower() for c in password):
        return False, "Le mot de passe doit contenir au moins une minuscule"
    
    if not any(c.isdigit() for c in password):
        return False, "Le mot de passe doit contenir au moins un chiffre"
    
    return True, "Mot de passe valide"

# Middleware pour la sécurité des headers
@app.after_request
def add_security_headers(response):
    """Ajouter des en-têtes de sécurité"""
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'SAMEORIGIN'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    
    # Content Security Policy
    csp = [
        "default-src 'self'",
        "script-src 'self' 'unsafe-inline' cdnjs.cloudflare.com",
        "style-src 'self' 'unsafe-inline' cdnjs.cloudflare.com fonts.googleapis.com",
        "font-src 'self' cdnjs.cloudflare.com fonts.gstatic.com",
        "img-src 'self' data:",
        "connect-src 'self'"
    ]
    
    if app.config.get('CSP_ENABLED', False):
        response.headers['Content-Security-Policy'] = '; '.join(csp)
    
    # HSTS
    if app.config.get('HSTS_ENABLED', False):
        response.headers['Strict-Transport-Security'] = f'max-age={app.config.get("HSTS_SECONDS", 31536000)}; includeSubDomains'
    
    return response

# Routes principales
@app.route('/')
def index():
    """Page d'accueil"""
    page = request.args.get('page', 1, type=int)
    per_page = 10
    
    journals = Journal.query.order_by(Journal.created_at.desc())\
        .paginate(page=page, per_page=per_page, error_out=False)
    
    return render_template('index.html', journals=journals)

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    """Inscription"""
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        username = request.form['username'].strip()
        email = request.form['email'].strip().lower()
        password = request.form['password']
        confirm_password = request.form.get('confirm_password', '')
        
        # Validation
        errors = []
        
        if not is_valid_username(username):
            errors.append('Nom d\'utilisateur invalide. Utilisez 3-20 caractères alphanumériques, tirets ou underscores.')
        
        if not is_valid_email(email):
            errors.append('Adresse email invalide.')
        
        password_valid, password_message = is_strong_password(password)
        if not password_valid:
            errors.append(password_message)
        
        if password != confirm_password:
            errors.append('Les mots de passe ne correspondent pas.')
        
        # Vérifier si l'utilisateur existe déjà
        existing_user = User.query.filter((User.email == email) | (User.username == username)).first()
        
        if existing_user:
            if existing_user.email == email:
                errors.append('Cet email est déjà utilisé.')
            else:
                errors.append('Ce nom d\'utilisateur est déjà pris.')
        
        if errors:
            for error in errors:
                flash(error, 'error')
            return render_template('signup.html', 
                                 username=username, 
                                 email=email)
        
        # Créer un nouvel utilisateur
        new_user = User(
            username=username,
            email=email,
            password=generate_password_hash(password, method='pbkdf2:sha256', salt_length=16)
        )
        
        try:
            db.session.add(new_user)
            db.session.commit()
            
            # Connecter automatiquement l'utilisateur
            login_user(new_user, remember=True)
            
            flash('Compte créé avec succès! Bienvenue!', 'success')
            return redirect(url_for('dashboard'))
            
        except Exception as e:
            db.session.rollback()
            app.logger.error(f'Erreur lors de l\'inscription: {str(e)}')
            flash('Une erreur est survenue lors de la création du compte.', 'error')
    
    return render_template('signup.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    """Connexion"""
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        email = request.form['email'].strip().lower()
        password = request.form['password']
        remember = 'remember' in request.form
        
        user = User.query.filter_by(email=email).first()
        
        if user and check_password_hash(user.password, password):
            login_user(user, remember=remember)
            
            # Redirection vers la page demandée ou dashboard
            next_page = request.args.get('next')
            if next_page and is_safe_url(next_page):
                return redirect(next_page)
            
            flash('Connexion réussie!', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Email ou mot de passe incorrect!', 'error')
            # Petit délai pour ralentir les attaques par force brute
            import time
            time.sleep(1)
    
    return render_template('login.html')

def is_safe_url(target):
    """Vérifier si l'URL est sûre pour la redirection"""
    from urllib.parse import urlparse, urljoin
    ref_url = urlparse(request.host_url)
    test_url = urlparse(urljoin(request.host_url, target))
    return test_url.scheme in ('http', 'https') and \
           ref_url.netloc == test_url.netloc

@app.route('/logout')
@login_required
def logout():
    """Déconnexion"""
    logout_user()
    flash('Vous avez été déconnecté.', 'info')
    return redirect(url_for('index'))

@app.route('/dashboard')
@login_required
def dashboard():
    """Tableau de bord utilisateur"""
    page = request.args.get('page', 1, type=int)
    per_page = 5
    
    user_journals = Journal.query.filter_by(user_id=current_user.id)\
        .order_by(Journal.created_at.desc())\
        .paginate(page=page, per_page=per_page, error_out=False)
    
    return render_template('dashboard.html', journals=user_journals)

@app.route('/journal/add', methods=['GET', 'POST'])
@login_required
def add_journal():
    """Ajouter un journal"""
    if request.method == 'POST':
        title = request.form['title'].strip()
        content = request.form['content'].strip()
        
        # Validation
        if not title or len(title) < 3:
            flash('Le titre doit contenir au moins 3 caractères.', 'error')
            return render_template('add_journal.html', title=title, content=content)
        
        if not content or len(content) < 10:
            flash('Le contenu doit contenir au moins 10 caractères.', 'error')
            return render_template('add_journal.html', title=title, content=content)
        
        if len(content) > 10000:
            flash('Le contenu est trop long (max 10000 caractères).', 'error')
            return render_template('add_journal.html', title=title, content=content)
        
        new_journal = Journal(
            title=title,
            content=content,
            user_id=current_user.id
        )
        
        try:
            db.session.add(new_journal)
            db.session.commit()
            
            flash('Journal publié avec succès!', 'success')
            return redirect(url_for('dashboard'))
            
        except Exception as e:
            db.session.rollback()
            app.logger.error(f'Erreur lors de la publication: {str(e)}')
            flash('Une erreur est survenue lors de la publication.', 'error')
    
    return render_template('add_journal.html')

@app.route('/journal/<int:journal_id>')
def view_journal(journal_id):
    """Voir un journal"""
    journal = Journal.query.get_or_404(journal_id)
    
    # Incrémenter le compteur de vues (simplifié)
    # En production, utiliser une table séparée pour les statistiques
    
    page = request.args.get('page', 1, type=int)
    per_page = 10
    
    comments = Comment.query.filter_by(journal_id=journal_id)\
        .order_by(Comment.created_at.desc())\
        .paginate(page=page, per_page=per_page, error_out=False)
    
    return render_template('journal.html', journal=journal, comments=comments)

@app.route('/journal/<int:journal_id>/comment', methods=['POST'])
@login_required
def add_comment(journal_id):
    """Ajouter un commentaire"""
    journal = Journal.query.get_or_404(journal_id)
    
    content = request.form['content'].strip()
    rating = request.form.get('rating', 5, type=int)
    
    # Validation
    if not content or len(content) < 3:
        flash('Le commentaire doit contenir au moins 3 caractères.', 'error')
        return redirect(url_for('view_journal', journal_id=journal_id))
    
    if len(content) > 1000:
        flash('Le commentaire est trop long (max 1000 caractères).', 'error')
        return redirect(url_for('view_journal', journal_id=journal_id))
    
    if rating < 1 or rating > 5:
        rating = 5
    
    new_comment = Comment(
        content=content,
        rating=rating,
        user_id=current_user.id,
        journal_id=journal_id
    )
    
    try:
        db.session.add(new_comment)
        db.session.commit()
        
        flash('Votre commentaire a été ajouté!', 'success')
        
    except Exception as e:
        db.session.rollback()
        app.logger.error(f'Erreur lors de l\'ajout du commentaire: {str(e)}')
        flash('Une erreur est survenue lors de l\'ajout du commentaire.', 'error')
    
    return redirect(url_for('view_journal', journal_id=journal_id))

@app.route('/journal/<int:journal_id>/delete')
@login_required
def delete_journal(journal_id):
    """Supprimer un journal"""
    journal = Journal.query.get_or_404(journal_id)
    
    # Vérifier que l'utilisateur est l'auteur
    if journal.user_id != current_user.id:
        flash('Vous n\'êtes pas autorisé à supprimer ce journal.', 'error')
        return redirect(url_for('dashboard'))
    
    try:
        db.session.delete(journal)
        db.session.commit()
        
        flash('Journal supprimé avec succès!', 'success')
        
    except Exception as e:
        db.session.rollback()
        app.logger.error(f'Erreur lors de la suppression: {str(e)}')
        flash('Une erreur est survenue lors de la suppression.', 'error')
    
    return redirect(url_for('dashboard'))

# Gestion d'erreurs
@app.errorhandler(404)
def page_not_found(e):
    return render_template('errors/404.html'), 404

@app.errorhandler(403)
def forbidden(e):
    return render_template('errors/403.html'), 403

@app.errorhandler(500)
def internal_server_error(e):
    return render_template('errors/500.html'), 500

# API Health Check
@app.route('/health')
def health_check():
    """Endpoint pour vérifier la santé de l'application"""
    try:
        # Vérifier la base de données
        db.session.execute('SELECT 1')
        return jsonify({
            'status': 'healthy',
            'database': 'connected',
            'timestamp': datetime.utcnow().isoformat()
        }), 200
    except Exception as e:
        return jsonify({
            'status': 'unhealthy',
            'database': 'disconnected',
            'error': str(e)
        }), 500

# Commande pour initialiser la base de données
@app.cli.command('init-db')
def init_db_command():
    """Initialiser la base de données"""
    with app.app_context():
        db.create_all()
    print('Base de données initialisée.')

@app.cli.command('create-admin')
def create_admin_command():
    """Créer un administrateur"""
    from getpass import getpass
    
    username = input('Nom d\'utilisateur: ')
    email = input('Email: ')
    password = getpass('Mot de passe: ')
    
    with app.app_context():
        # Vérifier si l'utilisateur existe déjà
        existing_user = User.query.filter((User.email == email) | (User.username == username)).first()
        if existing_user:
            print('L\'utilisateur existe déjà!')
            return
        
        # Créer l'admin
        admin = User(
            username=username,
            email=email,
            password=generate_password_hash(password, method='pbkdf2:sha256', salt_length=16)
        )
        
        db.session.add(admin)
        db.session.commit()
        print(f'Administrateur {username} créé avec succès!')

if __name__ == '__main__':
    # En production, utiliser gunicorn
    if app.config.get('ENV') == 'production':
        print("En production, utilisez: gunicorn -w 4 -b 0.0.0.0:5000 app:app")
    else:
        app.run(debug=True, host='0.0.0.0', port=5000)