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

