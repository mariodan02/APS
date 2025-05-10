from flask_login import UserMixin
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
import uuid
import json

db = SQLAlchemy()

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)  # In un'app reale, memorizzare password hashate
    role = db.Column(db.String(20), nullable=False)  # 'issuer', 'student', 'verifier', 'ca'
    public_key = db.Column(db.Text)  # Chiave pubblica (formato PEM)
    private_key = db.Column(db.Text)  # Chiave privata (formato PEM) - In un'app reale, non memorizzare questa
    
    # Campi aggiuntivi per gli studenti
    student_pseudonym = db.Column(db.String(80))  # Usato per la privacy
    student_hash_id = db.Column(db.String(120))  # Hash dell'ID reale dello studente

    # Campi aggiuntivi per le università
    university_did = db.Column(db.String(120))  # DID per le università
    university_name = db.Column(db.String(120))  # Nome completo
    university_country = db.Column(db.String(80))  # Paese

    credentials_issued = db.relationship('Credential', backref='issuer', foreign_keys='Credential.issuer_id')
    credentials_owned = db.relationship('Credential', backref='student', foreign_keys='Credential.student_id')
    
    def __repr__(self):
        return f'<User {self.username} ({self.role})>'

class Credential(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    uuid = db.Column(db.String(36), unique=True, nullable=False, default=lambda: str(uuid.uuid4()))
    issuer_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    student_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    
    # Metadati
    version = db.Column(db.String(10), default="1.2")
    issue_timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    expiration_date = db.Column(db.DateTime)
    status = db.Column(db.String(20), default="active")  # active, revoked, suspended
    
    # Attributi accademici
    course_code = db.Column(db.String(20))
    course_isced_code = db.Column(db.String(10))
    exam_grade = db.Column(db.String(10))
    exam_passed = db.Column(db.Boolean, default=True)
    exam_date = db.Column(db.DateTime)
    ects_credits = db.Column(db.Integer)
    
    # Dati crittografici
    signature = db.Column(db.Text)  # Firma digitale
    revocation_id = db.Column(db.String(36))  # ID per la revoca
    blockchain_reference = db.Column(db.String(150))  # Riferimento all'inserimento nella blockchain
    
    def to_dict(self):
        """Converte la credenziale in formato dizionario per la serializzazione JSON"""
        return {
            "metadati": {
                "versione": self.version,
                "identificativoUUID": self.uuid,
                "timestampEmissione": self.issue_timestamp.isoformat() + "Z",
                "dataFineValiditaChiave": self.expiration_date.isoformat() + "Z",
                "statoChiave": {
                    "registroDistribuitoURI": self.blockchain_reference,
                    "idRevoca": self.revocation_id
                },
                "firma": {
                    "algoritmo": "EdDSA",
                    "valore": self.signature
                }
            },
            "emittente": {
                "didUniversita": User.query.get(self.issuer_id).university_did,
                "chiavePubblica": User.query.get(self.issuer_id).public_key.split('\n')[1][:35] + '...',
                "urlDocumentoDID": f"https://did.{User.query.get(self.issuer_id).university_did.split(':')[2]}/v1/identifiers/{User.query.get(self.issuer_id).university_did}"
            },
            "soggetto": {
                "identificativoStudente": {
                    "hashIDReale": User.query.get(self.student_id).student_hash_id,
                    "identificativoPseudonimo": User.query.get(self.student_id).student_pseudonym,
                    "protezionePrivacy": "nessun_dato_personale_in_chiaro"
                },
                "destinatario": {
                    "chiavePubblicaStudente": User.query.get(self.student_id).public_key.split('\n')[1][:35] + '...'
                }
            },
            "attributiAccademici": {
                "codiceCorso": {
                    "codiceInterno": self.course_code,
                    "codiceISCED": self.course_isced_code
                },
                "votoEsame": {
                    "punteggio": self.exam_grade,
                    "superato": self.exam_passed
                },
                "dataSvolgimento": self.exam_date.isoformat() + "Z",
                "creditiECTS": self.ects_credits
            }
        }
    
    def to_json(self):
        return json.dumps(self.to_dict(), indent=2)
    
    def __repr__(self):
        return f'<Credential {self.uuid}>'

class RevocationRecord(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    credential_uuid = db.Column(db.String(36), unique=True, nullable=False)
    revocation_id = db.Column(db.String(36), unique=True, default=lambda: str(uuid.uuid4()))
    revocation_timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    reason = db.Column(db.String(200))
    revoker_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    transaction_hash = db.Column(db.String(64))  # Hash della transazione blockchain
    
    revoker = db.relationship('User')
    
    def __repr__(self):
        return f'<RevocationRecord {self.revocation_id}>'

class OCSPResponse(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    credential_uuid = db.Column(db.String(36), nullable=False)
    status = db.Column(db.String(20), nullable=False)  # good, revoked, unknown
    produced_at = db.Column(db.DateTime, default=datetime.utcnow)
    this_update = db.Column(db.DateTime, default=datetime.utcnow)
    next_update = db.Column(db.DateTime)
    signature = db.Column(db.Text)
    
    def __repr__(self):
        return f'<OCSPResponse {self.credential_uuid}>'

class BlockchainBlock(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    hash = db.Column(db.String(64), unique=True, nullable=False)
    previous_hash = db.Column(db.String(64), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    data = db.Column(db.Text)  # Dati JSON con informazioni sulla credenziale
    nonce = db.Column(db.Integer)
    
    def __repr__(self):
        return f'<BlockchainBlock {self.hash}>'