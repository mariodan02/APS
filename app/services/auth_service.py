# services/auth_service.py
from flask_jwt_extended import create_access_token
from models import User, University, Student, db
import hashlib
import uuid

class AuthService:
    @staticmethod
    def register_user(username, email, password, role, **kwargs):
        """Registra un nuovo utente nel sistema"""
        # Verifica se l'utente esiste già
        existing_user = User.query.filter((User.username == username) | (User.email == email)).first()
        if existing_user:
            return None, "Username o email già in uso"
        
        # Genera un DID per l'utente
        did_prefix = "did:web:" if role == "university" else "did:key:"
        did = f"{did_prefix}{username}.{str(uuid.uuid4())[:8]}"
        
        # Crea l'utente
        user = User(username=username, email=email, password=password, role=role)
        user.did = did
        user.public_key = kwargs.get('public_key', f"mock_public_key_{uuid.uuid4()}")
        
        # Salva l'utente
        db.session.add(user)
        db.session.flush()  # Per ottenere l'ID utente
        
        # Crea profilo specifico per ruolo
        if role == 'university':
            university = University(
                user_id=user.id,
                name=kwargs.get('name', f"Università di {username}"),
                country=kwargs.get('country', 'Italia'),
                did_document_url=kwargs.get('did_document_url', f"https://did.{username}.it/v1/identifiers/{did}")
            )
            db.session.add(university)
        
        elif role == 'student':
            # Genera hash dell'ID
            id_real = kwargs.get('id_real', f"id_{uuid.uuid4()}")
            id_hash = hashlib.sha256(id_real.encode()).hexdigest()
            
            student = Student(
                user_id=user.id,
                full_name=kwargs.get('full_name', f"Studente {username}"),
                id_hash=id_hash,
                pseudonym=f"student_{uuid.uuid4().hex[:8]}"
            )
            db.session.add(student)
        
        db.session.commit()
        return user, None
    
    @staticmethod
    def authenticate(username, password):
        """Autentica un utente e restituisce un token JWT"""
        user = User.query.filter_by(username=username).first()
        
        if not user or not user.check_password(password):
            return None, "Credenziali non valide"
        
        # Genera token JWT con ruolo dell'utente
        access_token = create_access_token(
            identity=username,
            additional_claims={"role": user.role, "user_id": user.id}
        )
        
        return {"access_token": access_token, "user": {"id": user.id, "role": user.role}}, None

# services/crypto_service.py
from Crypto.PublicKey import ECC
from Crypto.Signature import DSS
from Crypto.Hash import SHA256
import base64
import json
import uuid

class CryptoService:
    @staticmethod
    def generate_key_pair():
        """Genera una coppia di chiavi per firme Ed25519"""
        # In produzione si utilizzerebbe una vera libreria EdDSA
        # Per questo esempio usiamo ECC con curve P-256
        key = ECC.generate(curve='P-256')
        private_key = key.export_key(format='PEM')
        public_key = key.public_key().export_key(format='PEM')
        
        return {
            'private_key': private_key,
            'public_key': public_key
        }
    
    @staticmethod
    def sign_credential(credential_data, private_key_pem):
        """Firma i dati della credenziale con la chiave privata dell'emittente"""
        try:
            # Converti i dati in JSON e poi in bytes
            data_bytes = json.dumps(credential_data).encode('utf-8')
            
            # Crea l'hash dei dati
            h = SHA256.new(data_bytes)
            
            # Carica la chiave privata e firma
            key = ECC.import_key(private_key_pem)
            signer = DSS.new(key, 'fips-186-3')
            signature = signer.sign(h)
            
            # Codifica la firma in base64
            return base64.b64encode(signature).decode('utf-8')
        except Exception as e:
            print(f"Errore durante la firma: {str(e)}")
            return None
    
    @staticmethod
    def verify_signature(data, signature, public_key_pem):
        """Verifica la firma di una credenziale"""
        try:
            # Converti la firma da base64 a bytes
            signature_bytes = base64.b64decode(signature)
            
            # Converti i dati in JSON e poi in bytes
            data_bytes = json.dumps(data).encode('utf-8')
            
            # Crea l'hash dei dati
            h = SHA256.new(data_bytes)
            
            # Carica la chiave pubblica e verifica
            key = ECC.import_key(public_key_pem)
            verifier = DSS.new(key, 'fips-186-3')
            
            try:
                verifier.verify(h, signature_bytes)
                return True
            except ValueError:
                return False
        except Exception as e:
            print(f"Errore durante la verifica: {str(e)}")
            return False
    
    @staticmethod
    def generate_credential_id():
        """Genera un ID univoco per una credenziale"""
        return str(uuid.uuid4())

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
            Credenziale creata o None in caso di errore
        """
        try:
            # Verifica che l'emittente sia un'università
            issuer = User.query.get(issuer_id)
            if not issuer or not issuer.is_university():
                return None, "Solo le università possono emettere credenziali"
            
            # Verifica che il soggetto sia uno studente
            subject = User.query.get(subject_id)
            if not subject or not subject.is_student():
                return None, "Il destinatario deve essere uno studente"
            
            # Genera UUID per la credenziale e per revoca
            credential_uuid = str(uuid.uuid4())
            revocation_id = str(uuid.uuid4())
            
            # Prepara i dati per la firma
            data_to_sign = {
                "uuid": credential_uuid,
                "issuer_did": issuer.did,
                "subject_did": subject.did,
                "course_code": credential_data.get("course_code"),
                "exam_date": credential_data.get("exam_date"),
                "timestamp": datetime.utcnow().isoformat()
            }
            
            # Simula la firma dei dati (in produzione usare chiave privata reale)
            mock_private_key = private_key or "-----BEGIN PRIVATE KEY-----\nMOCK_KEY\n-----END PRIVATE KEY-----"
            signature = CryptoService.sign_credential(data_to_sign, mock_private_key)
            
            # Crea la nuova credenziale
            credential = Credential(
                uuid=credential_uuid,
                version="1.0",
                issuer_id=issuer_id,
                subject_id=subject_id,
                issued_at=datetime.utcnow(),
                valid_until=datetime.utcnow() + timedelta(days=365 * 3),  # 3 anni di validità
                course_code=credential_data.get("course_code"),
                course_iscee_code=credential_data.get("course_iscee_code"),
                exam_date=datetime.fromisoformat(credential_data.get("exam_date")),
                exam_score=credential_data.get("exam_score"),
                exam_passed=credential_data.get("exam_passed", True),
                ects_credits=credential_data.get("ects_credits"),
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
            
            db.session.add(credential)
            db.session.commit()
            
            return credential, None
        
        except Exception as e:
            db.session.rollback()
            return None, f"Errore durante l'emissione della credenziale: {str(e)}"
    
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