# services/credential_service.py
from models import db, Credential, RevocationRegistry, User, University, Student
from services.crypto_service import CryptoService
import uuid
from datetime import datetime, timedelta
import json

class CredentialService:
    @staticmethod
    def issue_credential(issuer_id, subject_id, credential_data, private_key=None):
        """
        Emette una nuova credenziale accademica
        
        Args:
            issuer_id: ID dell'università emittente
            subject_id: ID dello studente destinatario
            credential_data: Dati della credenziale
            private_key: Chiave privata per firmare (mock per demo)
        
        Returns:
            Tuple (Credential, str): Credenziale creata e messaggio di errore (None se successo)
        """
        try:
            # Validazione input
            if not issuer_id or not isinstance(issuer_id, int):
                return None, "ID emittente non valido"
            
            if not subject_id or not isinstance(subject_id, int):
                return None, "ID destinatario non valido"
            
            if not credential_data or not isinstance(credential_data, dict):
                return None, "Dati credenziale non validi"
            
            # Validazione campi obbligatori
            required_fields = ["course_code", "exam_date", "exam_score", "ects_credits"]
            for field in required_fields:
                if field not in credential_data or not credential_data[field]:
                    return None, f"Campo '{field}' obbligatorio"
            
            # Verifica che l'emittente sia un'università
            issuer = User.query.get(issuer_id)
            if not issuer:
                return None, "Emittente non trovato"
            
            if not issuer.is_university():
                return None, "Solo le università possono emettere credenziali"
            
            # Verifica che il soggetto sia uno studente
            subject = User.query.get(subject_id)
            if not subject:
                return None, "Destinatario non trovato"
            
            if not subject.is_student():
                return None, "Il destinatario deve essere uno studente"
            
            # Validazione dati specifici
            try:
                exam_date = datetime.fromisoformat(credential_data["exam_date"])
                
                # Verifica che la data non sia nel futuro
                if exam_date > datetime.utcnow():
                    return None, "La data dell'esame non può essere nel futuro"
                    
            except ValueError:
                return None, "Formato data esame non valido (richiesto ISO: YYYY-MM-DDTHH:MM:SS)"
            
            try:
                ects_credits = int(credential_data["ects_credits"])
                if ects_credits <= 0 or ects_credits > 30:
                    return None, "I crediti ECTS devono essere compresi tra 1 e 30"
            except ValueError:
                return None, "I crediti ECTS devono essere un numero intero"
            
            # Genera UUID per la credenziale e per revoca
            credential_uuid = str(uuid.uuid4())
            revocation_id = str(uuid.uuid4())
            
            # Prepara i dati per la firma
            data_to_sign = {
                "uuid": credential_uuid,
                "issuer_did": issuer.did,
                "subject_did": subject.did,
                "course_code": credential_data["course_code"],
                "exam_date": credential_data["exam_date"],
                "timestamp": datetime.utcnow().isoformat()
            }
            
            # Gestione della firma
            mock_private_key = private_key or "-----BEGIN PRIVATE KEY-----\nMOCK_KEY\n-----END PRIVATE KEY-----"
            signature = CryptoService.sign_credential(data_to_sign, mock_private_key)
            
            if not signature:
                return None, "Errore durante la firma della credenziale"
            
            # Data di emissione e scadenza
            issued_at = datetime.utcnow()
            valid_until = issued_at + timedelta(days=365 * 3)  # 3 anni di validità
            
            # Crea la nuova credenziale
            credential = Credential(
                uuid=credential_uuid,
                version="1.0",
                issuer_id=issuer_id,
                subject_id=subject_id,
                issued_at=issued_at,
                valid_until=valid_until,
                course_code=credential_data["course_code"],
                course_iscee_code=credential_data.get("course_iscee_code", ""),
                exam_date=exam_date,
                exam_score=credential_data["exam_score"],
                exam_passed=credential_data.get("exam_passed", True),
                ects_credits=ects_credits,
                signature=signature,
                revocation_id=revocation_id
            )
            
            # Crea metadati completi
            metadata = {
                "version": credential.version,
                "uuid": credential.uuid,
                "issuer": {
                    "did": issuer.did,
                    "name": issuer.university.name if hasattr(issuer, 'university') else None
                },
                "subject": {
                    "did": subject.did,
                    "pseudonym": subject.student.pseudonym if hasattr(subject, 'student') else None
                },
                "issuance_date": credential.issued_at.isoformat(),
                "valid_until": credential.valid_until.isoformat(),
                "revocation_id": credential.revocation_id,
                "signature": {
                    "algorithm": "EdDSA",
                    "value": signature
                }
            }
            credential.set_metadata(metadata)
            
            try:
                db.session.add(credential)
                db.session.commit()
                return credential, None
            except Exception as db_error:
                db.session.rollback()
                return None, f"Errore durante il salvataggio nel database: {str(db_error)}"
            
        except Exception as e:
            db.session.rollback()
            return None, f"Errore imprevisto durante l'emissione della credenziale: {str(e)}"

    @staticmethod
    def get_credential(credential_id):
        """Ottiene una credenziale dal database"""
        return Credential.query.get(credential_id)
    
    @staticmethod
    def get_credential_by_uuid(uuid):
        """Ottiene una credenziale dal database tramite UUID"""
        return Credential.query.filter_by(uuid=uuid).first()
    
    @staticmethod
    def get_student_credentials(student_id):
        """Ottiene tutte le credenziali di uno studente"""
        return Credential.query.filter_by(subject_id=student_id).all()
    
    @staticmethod
    def get_university_issued_credentials(university_id):
        """Ottiene tutte le credenziali emesse da un'università"""
        return Credential.query.filter_by(issuer_id=university_id).all()
    
    @staticmethod
    def revoke_credential(credential_uuid, revoker_id, reason=None):
        """Revoca una credenziale"""
        credential = Credential.query.filter_by(uuid=credential_uuid).first()
        
        if not credential:
            return False, "Credenziale non trovata"
        
        # Verifica che il revocante sia l'emittente o un'autorità
        revoker = User.query.get(revoker_id)
        if not revoker or (revoker.id != credential.issuer_id and not revoker.is_authority()):
            return False, "Non autorizzato a revocare questa credenziale"
        
        # Se la credenziale è già revocata, restituisci errore
        if credential.revoked:
            return False, "Credenziale già revocata"
        
        # Aggiorna lo stato della credenziale
        credential.revoked = True
        
        # Crea una voce nel registro delle revoche
        revocation = RevocationRegistry(
            credential_uuid=credential_uuid,
            revocation_id=credential.revocation_id,
            reason=reason,
            revoker_id=revoker_id
        )
        
        db.session.add(revocation)
        db.session.commit()
        
        return True, "Credenziale revocata con successo"
    
    @staticmethod
    def verify_credential(credential_uuid, public_key=None):
        """
        Verifica una credenziale
        
        Returns:
            (bool, str): Tupla con stato di verifica e messaggio
        """
        credential = Credential.query.filter_by(uuid=credential_uuid).first()
        
        if not credential:
            return False, "Credenziale non trovata"
        
        # Verifica che la credenziale non sia revocata
        if RevocationRegistry.is_revoked(credential_uuid):
            return False, "Credenziale revocata"
        
        # Verifica che la credenziale non sia scaduta
        if credential.valid_until and credential.valid_until < datetime.utcnow():
            return False, "Credenziale scaduta"
        
        # Verifica la firma (in produzione)
        # In questo esempio simuliamo una verifica sempre positiva
        if public_key:
            # Dati originali che sono stati firmati
            data_to_verify = {
                "uuid": credential.uuid,
                "issuer_did": credential.issuer.did,
                "subject_did": credential.subject.did,
                "course_code": credential.course_code,
                "exam_date": credential.exam_date.isoformat(),
                "timestamp": credential.issued_at.isoformat()
            }
            
            # Verifica la firma
            signature_valid = CryptoService.verify_signature(
                data_to_verify, 
                credential.signature, 
                public_key
            )
            
            if not signature_valid:
                return False, "Firma non valida"
        
        return True, "Credenziale valida"
    
    @staticmethod
    def create_selective_disclosure(credential_id, disclosed_fields):
        """
        Crea una presentazione con divulgazione selettiva
        
        Args:
            credential_id: ID della credenziale
            disclosed_fields: Lista dei campi da mostrare
        
        Returns:
            JSON della presentazione selettiva
        """
        credential = Credential.query.get(credential_id)
        if not credential:
            return None, "Credenziale non trovata"
        
        # Ottieni il JSON completo della credenziale
        full_credential = credential.to_json(include_private=True)
        
        # Crea una versione selettiva con solo i campi richiesti
        selective_presentation = {"metadati": {}}
        
        # Includi sempre i metadati essenziali
        selective_presentation["metadati"]["versione"] = full_credential["metadati"]["versione"]
        selective_presentation["metadati"]["identificativoUUID"] = full_credential["metadati"]["identificativoUUID"]
        selective_presentation["metadati"]["firma"] = full_credential["metadati"]["firma"]
        
        # Includi i campi emittente richiesti
        if "emittente" in disclosed_fields:
            selective_presentation["emittente"] = full_credential["emittente"]
        
        # Includi i campi accademici richiesti
        selective_presentation["attributiAccademici"] = {}
        
        for field in disclosed_fields:
            if field.startswith("attributiAccademici."):
                parts = field.split(".")
                if len(parts) >= 2:
                    main_field = parts[1]
                    if main_field in full_credential["attributiAccademici"]:
                        # Gestisci campi nidificati
                        if len(parts) > 2:
                            sub_field = parts[2]
                            if main_field not in selective_presentation["attributiAccademici"]:
                                selective_presentation["attributiAccademici"][main_field] = {}
                            
                            if sub_field in full_credential["attributiAccademici"][main_field]:
                                selective_presentation["attributiAccademici"][main_field][sub_field] = \
                                    full_credential["attributiAccademici"][main_field][sub_field]
                        else:
                            # Campo principale
                            selective_presentation["attributiAccademici"][main_field] = \
                                full_credential["attributiAccademici"][main_field]
        
        return selective_presentation, None