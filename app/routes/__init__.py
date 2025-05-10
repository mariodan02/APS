# routes/__init__.py
from flask import Blueprint

# Creazione dei Blueprint
auth_bp = Blueprint('auth', __name__, url_prefix='/api/auth')
student_bp = Blueprint('student', __name__, url_prefix='/api/student')
university_bp = Blueprint('university', __name__, url_prefix='/api/university')
verifier_bp = Blueprint('verifier', __name__, url_prefix='/api/verifier')

# Importa le route
from .auth_routes import *
from .student_routes import *
from .university_routes import *
from .verifier_routes import *

# routes/auth_routes.py
from flask import request, jsonify
from flask_jwt_extended import jwt_required, get_jwt_identity, get_jwt
from models import User
from services.auth_service import AuthService
from . import auth_bp

@auth_bp.route('/register', methods=['POST'])
def register():
    data = request.json
    
    if not data or not all(k in data for k in ['username', 'email', 'password', 'role']):
        return jsonify({"error": "Dati mancanti"}), 400
    
    # Parametri aggiuntivi basati sul ruolo
    kwargs = {}
    if data['role'] == 'university':
        kwargs.update({
            'name': data.get('name'),
            'country': data.get('country'),
            'did_document_url': data.get('did_document_url')
        })
    elif data['role'] == 'student':
        kwargs.update({
            'full_name': data.get('full_name'),
            'id_real': data.get('id_real')
        })
    
    # Registra l'utente
    user, error = AuthService.register_user(
        data['username'], 
        data['email'], 
        data['password'], 
        data['role'],
        **kwargs
    )
    
    if error:
        return jsonify({"error": error}), 400
    
    return jsonify({
        "message": "Utente registrato con successo",
        "user_id": user.id,
        "username": user.username,
        "role": user.role,
        "did": user.did
    }), 201

@auth_bp.route('/login', methods=['POST'])
def login():
    data = request.json
    
    if not data or not all(k in data for k in ['username', 'password']):
        return jsonify({"error": "Dati mancanti"}), 400
    
    # Autentica l'utente
    result, error = AuthService.authenticate(data['username'], data['password'])
    
    if error:
        return jsonify({"error": error}), 401
    
    return jsonify(result), 200

@auth_bp.route('/me', methods=['GET'])
@jwt_required()
def get_current_user():
    # Ottieni l'identità dell'utente dal token JWT
    current_user = get_jwt_identity()
    claims = get_jwt()
    
    # Trova l'utente nel database
    user = User.query.filter_by(username=current_user).first()
    
    if not user:
        return jsonify({"error": "Utente non trovato"}), 404
    
    # Prepara i dati dell'utente
    user_data = {
        "id": user.id,
        "username": user.username,
        "email": user.email,
        "role": user.role,
        "did": user.did
    }
    
    # Aggiungi dati specifici per ruolo
    if user.role == 'university' and hasattr(user, 'university'):
        user_data.update({
            "name": user.university.name,
            "country": user.university.country
        })
    elif user.role == 'student' and hasattr(user, 'student'):
        user_data.update({
            "full_name": user.student.full_name,
            "pseudonym": user.student.pseudonym
        })
    
    return jsonify(user_data), 200

# routes/student_routes.py
from flask import request, jsonify
from flask_jwt_extended import jwt_required, get_jwt
from models import User
from services.credential_service import CredentialService
from . import student_bp

def check_student_role():
    """Verifica che l'utente abbia il ruolo di studente"""
    claims = get_jwt()
    if claims['role'] != 'student':
        return jsonify({"error": "Accesso negato. Richiesto ruolo di studente"}), 403
    return None

@student_bp.route('/credentials', methods=['GET'])
@jwt_required()
def get_credentials():
    # Verifica il ruolo
    error_response = check_student_role()
    if error_response:
        return error_response
    
    # Ottieni ID dell'utente
    claims = get_jwt()
    student_id = claims['user_id']
    
    # Ottieni credenziali dello studente
    credentials = CredentialService.get_student_credentials(student_id)
    
    # Converti le credenziali in JSON
    credentials_json = [
        {
            "id": cred.id,
            "uuid": cred.uuid,
            "course_code": cred.course_code,
            "exam_score": cred.exam_score,
            "exam_date": cred.exam_date.isoformat(),
            "ects_credits": cred.ects_credits,
            "issuer": cred.issuer.username if cred.issuer else None,
            "issued_at": cred.issued_at.isoformat(),
            "revoked": cred.revoked
        } for cred in credentials
    ]
    
    return jsonify(credentials_json), 200

@student_bp.route('/credentials/<int:credential_id>', methods=['GET'])
@jwt_required()
def get_credential(credential_id):
    # Verifica il ruolo
    error_response = check_student_role()
    if error_response:
        return error_response
    
    # Ottieni ID dell'utente
    claims = get_jwt()
    student_id = claims['user_id']
    
    # Ottieni la credenziale
    credential = CredentialService.get_credential(credential_id)
    
    if not credential:
        return jsonify({"error": "Credenziale non trovata"}), 404
    
    # Verifica che la credenziale appartenga allo studente
    if credential.subject_id != student_id:
        return jsonify({"error": "Non autorizzato ad accedere a questa credenziale"}), 403
    
    # Converti la credenziale in JSON
    credential_json = credential.to_json(include_private=True)
    
    return jsonify(credential_json), 200

@student_bp.route('/credentials/<int:credential_id>/selective', methods=['POST'])
@jwt_required()
def create_selective_disclosure(credential_id):
    # Verifica il ruolo
    error_response = check_student_role()
    if error_response:
        return error_response
    
    # Ottieni ID dell'utente
    claims = get_jwt()
    student_id = claims['user_id']
    
    # Ottieni la credenziale
    credential = CredentialService.get_credential(credential_id)
    
    if not credential:
        return jsonify({"error": "Credenziale non trovata"}), 404
    
    # Verifica che la credenziale appartenga allo studente
    if credential.subject_id != student_id:
        return jsonify({"error": "Non autorizzato ad accedere a questa credenziale"}), 403
    
    # Ottieni i campi da divulgare
    data = request.json
    if not data or 'disclosed_fields' not in data:
        return jsonify({"error": "Campi da divulgare non specificati"}), 400
    
    disclosed_fields = data['disclosed_fields']
    
    # Crea la presentazione selettiva
    presentation, error = CredentialService.create_selective_disclosure(credential_id, disclosed_fields)
    
    if error:
        return jsonify({"error": error}), 400
    
    return jsonify(presentation), 200

# routes/university_routes.py
from flask import request, jsonify
from flask_jwt_extended import jwt_required, get_jwt
from models import User
from services.credential_service import CredentialService
from . import university_bp

def check_university_role():
    """Verifica che l'utente abbia il ruolo di università"""
    claims = get_jwt()
    if claims['role'] != 'university':
        return jsonify({"error": "Accesso negato. Richiesto ruolo di università"}), 403
    return None

@university_bp.route('/students', methods=['GET'])
@jwt_required()
def get_students():
    # Verifica il ruolo
    error_response = check_university_role()
    if error_response:
        return error_response
    
    # Ottieni tutti gli utenti con ruolo studente
    students = User.query.filter_by(role='student').all()
    
    # Converti gli studenti in JSON
    students_json = [
        {
            "id": student.id,
            "username": student.username,
            "did": student.did,
            "pseudonym": student.student.pseudonym if hasattr(student, 'student') else None
        } for student in students
    ]
    
    return jsonify(students_json), 200

@university_bp.route('/credentials/issue', methods=['POST'])
@jwt_required()
def issue_credential():
    # Verifica il ruolo
    error_response = check_university_role()
    if error_response:
        return error_response
    
    # Ottieni ID dell'università
    claims = get_jwt()
    university_id = claims['user_id']
    
    # Verifica i dati della richiesta
    data = request.json
    if not data or not all(k in data for k in ['subject_id', 'course_code', 'exam_date', 'exam_score', 'ects_credits']):
        return jsonify({"error": "Dati mancanti"}), 400
    
    # Emetti la credenziale
    credential, error = CredentialService.issue_credential(
        university_id,
        data['subject_id'],
        {
            "course_code": data['course_code'],
            "course_iscee_code": data.get('course_iscee_code'),
            "exam_date": data['exam_date'],
            "exam_score": data['exam_score'],
            "exam_passed": data.get('exam_passed', True),
            "ects_credits": data['ects_credits']
        }
    )
    
    if error:
        return jsonify({"error": error}), 400
    
    return jsonify({
        "message": "Credenziale emessa con successo",
        "credential_id": credential.id,
        "credential_uuid": credential.uuid
    }), 201

@university_bp.route('/credentials/issued', methods=['GET'])
@jwt_required()
def get_issued_credentials():
    # Verifica il ruolo
    error_response = check_university_role()
    if error_response:
        return error_response
    
    # Ottieni ID dell'università
    claims = get_jwt()
    university_id = claims['user_id']
    
    # Ottieni credenziali emesse dall'università
    credentials = CredentialService.get_university_issued_credentials(university_id)
    
    # Converti le credenziali in JSON
    credentials_json = [
        {
            "id": cred.id,
            "uuid": cred.uuid,
            "course_code": cred.course_code,
            "student": cred.subject.username if cred.subject else None,
            "exam_score": cred.exam_score,
            "exam_date": cred.exam_date.isoformat(),
            "issued_at": cred.issued_at.isoformat(),
            "revoked": cred.revoked
        } for cred in credentials
    ]
    
    return jsonify(credentials_json), 200

@university_bp.route('/credentials/<uuid:credential_uuid>/revoke', methods=['POST'])
@jwt_required()
def revoke_credential(credential_uuid):
    # Verifica il ruolo
    error_response = check_university_role()
    if error_response:
        return error_response
    
    # Ottieni ID dell'università
    claims = get_jwt()
    university_id = claims['user_id']
    
    # Ottieni motivo della revoca
    data = request.json or {}
    reason = data.get('reason')
    
    # Revoca la credenziale
    success, message = CredentialService.revoke_credential(
        str(credential_uuid),
        university_id,
        reason
    )
    
    if not success:
        return jsonify({"error": message}), 400
    
    return jsonify({"message": message}), 200

# routes/verifier_routes.py
from flask import request, jsonify
from flask_jwt_extended import jwt_required, get_jwt
from services.credential_service import CredentialService
from . import verifier_bp

@verifier_bp.route('/verify', methods=['POST'])
@jwt_required()
def verify_credential():
    data = request.json
    
    if not data or 'credential_uuid' not in data:
        return jsonify({"error": "UUID della credenziale mancante"}), 400
    
    credential_uuid = data['credential_uuid']
    public_key = data.get('public_key')  # Opzionale per la verifica della firma
    
    # Verifica la credenziale
    valid, message = CredentialService.verify_credential(credential_uuid, public_key)
    
    return jsonify({
        "valid": valid,
        "message": message
    }), 200 if valid else 400

@verifier_bp.route('/verify-presentation', methods=['POST'])
@jwt_required()
def verify_presentation():
    data = request.json
    
    if not data or 'presentation' not in data:
        return jsonify({"error": "Presentazione mancante"}), 400
    
    presentation = data['presentation']
    
    # Estrai UUID dalla presentazione
    if not presentation or 'metadati' not in presentation or 'identificativoUUID' not in presentation['metadati']:
        return jsonify({"error": "Formato presentazione non valido"}), 400
    
    credential_uuid = presentation['metadati']['identificativoUUID']
    
    # Verifica che la credenziale esista e sia valida
    valid, message = CredentialService.verify_credential(credential_uuid)
    
    if not valid:
        return jsonify({
            "valid": False,
            "message": message
        }), 400
    
    # Qui in un sistema reale si verificherebbe anche la validità della presentazione selettiva
    # e che i campi dichiarati corrispondano a quelli nella credenziale originale
    
    return jsonify({
        "valid": True,
        "message": "Presentazione valida"
    }), 200