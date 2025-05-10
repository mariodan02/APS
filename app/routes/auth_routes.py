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

