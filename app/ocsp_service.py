from flask import Blueprint, request, jsonify
from models import db, OCSPResponse, Credential, User
from datetime import datetime, timedelta
from crypto_utils import sign_data, verify_signature
import json
from blockchain import SimpleBlockchain

ocsp = Blueprint('ocsp', __name__)

@ocsp.route('/api/ocsp/check', methods=['POST'])
def check_credential():
    """OCSP endpoint to check credential status"""
    
    # Get request data
    data = request.json
    if not data or 'credential_uuid' not in data:
        return jsonify({"error": "Missing credential_uuid"}), 400
    
    credential_uuid = data['credential_uuid']
    
    # Check if credential exists
    credential = Credential.query.filter_by(uuid=credential_uuid).first()
    if not credential:
        # Create unknown status response
        return create_ocsp_response(credential_uuid, "unknown", None)
    
    # Check blockchain for credential status
    blockchain = SimpleBlockchain()
    status = blockchain.verify_credential(credential_uuid)
    
    # Create and store OCSP response
    return create_ocsp_response(credential_uuid, status, credential)

def create_ocsp_response(credential_uuid, status, credential=None):
    """Create an OCSP response for a credential"""
    
    # Get CA user for signing
    ca_user = User.query.filter_by(role='ca').first()
    if not ca_user:
        return jsonify({"error": "CA not found"}), 500
    
    # Prepare response data
    now = datetime.utcnow()
    response_data = {
        "responseStatus": "successful",
        "responseType": "BasicOCSPResponse",
        "version": 1,
        "responderID": ca_user.university_did,
        "producedAt": now.isoformat() + "Z",
        "responses": [
            {
                "certID": {
                    "hashAlgorithm": "sha256",
                    "issuerNameHash": credential.issuer.university_did if credential else "",
                    "issuerKeyHash": "",
                    "serialNumber": credential_uuid
                },
                "certStatus": status,
                "thisUpdate": now.isoformat() + "Z",
                "nextUpdate": (now + timedelta(hours=24)).isoformat() + "Z"
            }
        ]
    }
    
    # Sign the response
    signature = sign_data(ca_user.private_key, json.dumps(response_data))
    
    # Add signature to response
    response_data["signature"] = {
        "algorithm": "Ed25519",
        "value": signature
    }
    
    # Store OCSP response in database
    ocsp_response = OCSPResponse(
        credential_uuid=credential_uuid,
        status=status,
        produced_at=now,
        this_update=now,
        next_update=now + timedelta(hours=24),
        signature=signature
    )
    
    db.session.add(ocsp_response)
    db.session.commit()
    
    return jsonify(response_data)

@ocsp.route('/api/ocsp/history/<credential_uuid>', methods=['GET'])
def get_ocsp_history(credential_uuid):
    """Get OCSP response history for a credential"""
    
    responses = OCSPResponse.query.filter_by(credential_uuid=credential_uuid).order_by(OCSPResponse.produced_at.desc()).all()
    
    history = []
    for response in responses:
        history.append({
            "status": response.status,
            "produced_at": response.produced_at.isoformat() + "Z",
            "this_update": response.this_update.isoformat() + "Z",
            "next_update": response.next_update.isoformat() + "Z"
        })
    
    return jsonify({"credential_uuid": credential_uuid, "history": history})