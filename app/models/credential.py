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