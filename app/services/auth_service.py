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


