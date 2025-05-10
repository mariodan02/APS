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