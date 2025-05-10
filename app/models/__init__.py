# models/__init__.py
from flask_sqlalchemy import SQLAlchemy
from flask_jwt_extended import JWTManager

db = SQLAlchemy()
jwt = JWTManager()

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

# models/credential.py
from . import db
import json
from datetime import datetime

class Credential(db.Model):
    __tablename__ = 'credentials'
    
    id = db.Column(db.Integer, primary_key=True)
    uuid = db.Column(db.String(36), nullable=False, unique=True)
    version = db.Column(db.String(10), nullable=False)
    issuer_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    subject_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    issued_at = db.Column(db.DateTime, default=datetime.utcnow)
    valid_until = db.Column(db.DateTime, nullable=True)
    revoked = db.Column(db.Boolean, default=False)
    
    # Campi credenziale
    course_code = db.Column(db.String(20), nullable=False)
    course_iscee_code = db.Column(db.String(10), nullable=True)
    exam_date = db.Column(db.DateTime, nullable=False)
    exam_score = db.Column(db.String(10), nullable=False)
    exam_passed = db.Column(db.Boolean, default=True)
    ects_credits = db.Column(db.Integer, nullable=False)
    
    # Dati crittografici
    signature = db.Column(db.Text, nullable=False)  # Firma dell'emittente
    revocation_id = db.Column(db.String(36), nullable=True)  # ID per la revoca
    
    # Metadati completi (JSON)
    metadata_json = db.Column(db.Text, nullable=False)
    
    def get_metadata(self):
        return json.loads(self.metadata_json)
    
    def set_metadata(self, metadata_dict):
        self.metadata_json = json.dumps(metadata_dict)
    
    def to_json(self, include_private=False):
        """Converti la credenziale in formato JSON"""
        credential = {
            "metadati": {
                "versione": self.version,
                "identificativoUUID": self.uuid,
                "timestampEmissione": self.issued_at.isoformat(),
                "dataFineValiditaChiave": self.valid_until.isoformat() if self.valid_until else None,
                "statoChiave": {
                    "registroDistribuitoURI": "did:ethr:revocationRegistry:0x7a8c8d3b48",
                    "idRevoca": self.revocation_id
                },
                "firma": {
                    "algoritmo": "EdDSA",
                    "valore": self.signature
                }
            },
            "attributiAccademici": {
                "codiceCorso": {
                    "codiceInterno": self.course_code,
                    "codiceISCED": self.course_iscee_code
                },
                "votoEsame": {
                    "punteggio": self.exam_score,
                    "superato": self.exam_passed
                },
                "dataSvolgimento": self.exam_date.isoformat(),
                "creditiECTS": self.ects_credits
            }
        }
        
        # Aggiungi informazioni dell'emittente e del soggetto 
        # (queste verrebbero caricate dal database ma qui le simuliamo)
        if self.issuer:
            credential["emittente"] = {
                "didUniversita": self.issuer.did,
                "chiavePubblica": self.issuer.public_key,
                "urlDocumentoDID": University.query.filter_by(user_id=self.issuer.id).first().did_document_url
            }
        
        if include_private and self.subject:
            student = Student.query.filter_by(user_id=self.subject.id).first()
            credential["soggetto"] = {
                "identificativoStudente": {
                    "hashIDReale": student.id_hash,
                    "identificativoPseudonimo": student.pseudonym,
                    "protezionePrivacy": "nessun_dato_personale_in_chiaro"
                },
                "destinatario": {
                    "chiavePubblicaStudente": self.subject.public_key
                }
            }
        
        return credential

# models/revocation.py
from . import db
from datetime import datetime

class RevocationRegistry(db.Model):
    __tablename__ = 'revocation_registry'
    
    id = db.Column(db.Integer, primary_key=True)
    credential_uuid = db.Column(db.String(36), nullable=False, index=True)
    revocation_id = db.Column(db.String(36), nullable=False, unique=True)
    revoked_at = db.Column(db.DateTime, default=datetime.utcnow)
    reason = db.Column(db.String(255), nullable=True)
    revoker_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    
    # Relazione con l'utente che ha effettuato la revoca
    revoker = db.relationship('User')
    
    @staticmethod
    def is_revoked(credential_uuid):
        """Controlla se una credenziale è stata revocata"""
        return RevocationRegistry.query.filter_by(credential_uuid=credential_uuid).first() is not None