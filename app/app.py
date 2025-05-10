# app.py
from flask import Flask, render_template, redirect, url_for, request, jsonify
from flask_cors import CORS
from config import Config
from models import db, jwt
from routes import auth_bp, student_bp, university_bp, verifier_bp
from services.revocation_service import revocation_registry_bp
import os

# Crea l'applicazione Flask
app = Flask(__name__)
app.config.from_object(Config)

# Assicurati che la directory dei dati esista
os.makedirs(os.path.join(os.path.dirname(__file__), 'data'), exist_ok=True)

# Inizializza estensioni
CORS(app)
db.init_app(app)
jwt.init_app(app)

# Registra i blueprint
app.register_blueprint(auth_bp)
app.register_blueprint(student_bp)
app.register_blueprint(university_bp)
app.register_blueprint(verifier_bp)
app.register_blueprint(revocation_registry_bp)

# Crea le tabelle del database e inizializza con dati di esempio
@app.before_first_request
def setup_database():
    db.create_all()
    
    # Aggiungi dati di esempio solo se il database è vuoto
    from models import User
    if User.query.count() == 0:
        create_sample_data()

def create_sample_data():
    """Crea dati di esempio per il sistema"""
    from services.auth_service import AuthService
    from services.credential_service import CredentialService
    from models import User, Student, University
    from datetime import datetime, timedelta
    
    print("Inizializzazione database con dati di esempio...")
    
    try:
        # Crea università di esempio
        unisa, _ = AuthService.register_user(
            username="unisa",
            email="info@unisa.it",
            password="password",
            role="university",
            name="Università di Salerno",
            country="Italia",
            did_document_url="https://did.unisa.it/v1/identifiers/did:web:unisa.it"
        )
        
        rennes, _ = AuthService.register_user(
            username="rennes",
            email="info@univ-rennes.fr",
            password="password",
            role="university",
            name="Université de Rennes",
            country="Francia",
            did_document_url="https://did.univ-rennes.fr/v1/identifiers/did:web:univ-rennes.fr"
        )
        
        # Crea studenti di esempio
        mario, _ = AuthService.register_user(
            username="mario",
            email="mario@studenti.unisa.it",
            password="password",
            role="student",
            full_name="Mario Rossi",
            id_real="RSSMRA98T10H703S"
        )
        
        laura, _ = AuthService.register_user(
            username="laura",
            email="laura@studenti.unisa.it",
            password="password",
            role="student",
            full_name="Laura Bianchi",
            id_real="BNCLRA99M49F839X"
        )
        
        # Crea autorità di esempio
        authority, _ = AuthService.register_user(
            username="erasmus",
            email="admin@erasmus.eu",
            password="password",
            role="authority"
        )
        
        # Emetti credenziali di esempio
        today = datetime.utcnow()
        
        # Credenziali emesse da Rennes per Mario
        CredentialService.issue_credential(
            rennes.id,
            mario.id,
            {
                "course_code": "INF/01-ASD",
                "course_iscee_code": "0613",
                "exam_date": (today - timedelta(days=60)).isoformat(),
                "exam_score": "28/30",
                "ects_credits": 6
            }
        )
        
        CredentialService.issue_credential(
            rennes.id,
            mario.id,
            {
                "course_code": "MAT/03",
                "course_iscee_code": "0541",
                "exam_date": (today - timedelta(days=45)).isoformat(),
                "exam_score": "30/30",
                "ects_credits": 9
            }
        )
        
        # Credenziali emesse da Unisa per Laura
        credential, _ = CredentialService.issue_credential(
            unisa.id,
            laura.id,
            {
                "course_code": "FIS/01",
                "course_iscee_code": "0533",
                "exam_date": (today - timedelta(days=30)).isoformat(),
                "exam_score": "25/30",
                "ects_credits": 6
            }
        )
        
        # Revoca una credenziale per esempio
        CredentialService.revoke_credential(
            credential.uuid,
            unisa.id,
            "Errore nelle procedure di valutazione"
        )
        
        print("Dati di esempio creati con successo!")
        
    except Exception as e:
        print(f"Errore durante la creazione dei dati di esempio: {str(e)}")
        db.session.rollback()


@app.route('/')
def index():
    return render_template('index.html')

@app.route('/login')
def login_page():
    return render_template('login.html')

@app.route('/register')
def register_page():
    return render_template('register.html')

@app.route('/dashboard')
def dashboard():
    return render_template('dashboard.html')

@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html'), 404

@app.errorhandler(500)
def internal_server_error(e):
    return render_template('500.html'), 500

# Endpoint pubblico per verificare lo stato API
@app.route('/api/status')
def api_status():
    return jsonify({
        "status": "online",
        "version": "1.0.0",
        "name": "Academic Credentials API"
    })

if __name__ == '__main__':
    app.run(debug=True)