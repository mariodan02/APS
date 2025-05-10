# models/user.py
from . import db
from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash

class User(db.Model):
    __tablename__ = 'users'
    
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), unique=True, index=True)
    email = db.Column(db.String(120), unique=True, index=True)
    password_hash = db.Column(db.String(128))
    role = db.Column(db.String(20), nullable=False)  # 'student', 'university', 'authority'
    did = db.Column(db.String(100), unique=True, nullable=True)  # Decentralized ID
    public_key = db.Column(db.Text, nullable=True)  # Public key for verification
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Relazioni
    issued_credentials = db.relationship('Credential', 
                                         foreign_keys='Credential.issuer_id',
                                         backref='issuer', lazy='dynamic')
    
    received_credentials = db.relationship('Credential', 
                                          foreign_keys='Credential.subject_id',
                                          backref='subject', lazy='dynamic')
    
    def __init__(self, username, email, password, role):
        self.username = username
        self.email = email
        self.set_password(password)
        self.role = role
    
    def set_password(self, password):
        self.password_hash = generate_password_hash(password)
    
    def check_password(self, password):
        return check_password_hash(self.password_hash, password)
    
    def is_university(self):
        return self.role == 'university'
    
    def is_student(self):
        return self.role == 'student'
    
    def is_authority(self):
        return self.role == 'authority'

class University(db.Model):
    __tablename__ = 'universities'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    name = db.Column(db.String(100), nullable=False)
    country = db.Column(db.String(50), nullable=False)
    did_document_url = db.Column(db.String(255), nullable=True)
    
    # Collegamento uno-a-uno con User
    user = db.relationship('User', backref=db.backref('university', uselist=False))

class Student(db.Model):
    __tablename__ = 'students'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    full_name = db.Column(db.String(100), nullable=False)
    id_hash = db.Column(db.String(64), nullable=False, unique=True)  # Hash dell'ID reale
    pseudonym = db.Column(db.String(64), nullable=True)  # Identificativo pseudonimo
    
    # Collegamento uno-a-uno con User
    user = db.relationship('User', backref=db.backref('student', uselist=False))

