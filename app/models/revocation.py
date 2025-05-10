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