# config.py
import os
from datetime import timedelta

class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY', 'chiave-dev-molto-sicura-da-cambiare')
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL', 'sqlite:///academic_credentials.db')
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    JWT_SECRET_KEY = os.environ.get('JWT_SECRET_KEY', 'jwt-chiave-dev-sicura-da-cambiare')
    JWT_ACCESS_TOKEN_EXPIRES = timedelta(hours=1)
    
    # Configurazioni per gli algoritmi crittografici
    CRYPTO_KEY_ALGORITHM = 'EdDSA'  # Ed25519 per firme digitali
    HASH_ALGORITHM = 'SHA-256'      # Per hash ID e altre operazioni

# requirements.txt
"""
flask==2.3.3
flask-sqlalchemy==3.1.1
flask-jwt-extended==4.5.3
flask-cors==4.0.0
pycryptodome==3.19.0
py-multibase==1.0.3
python-dateutil==2.8.2
validators==0.22.0
werkzeug==2.3.7
gunicorn==21.2.0
"""