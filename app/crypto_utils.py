import datetime
from cryptography.hazmat.primitives.asymmetric import rsa, ed25519
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.serialization import load_pem_private_key, load_pem_public_key
from cryptography.exceptions import InvalidSignature
import base64
import hashlib
import json
import os
import uuid

def generate_keypair():
    """Generate Ed25519 key pair for digital signatures"""
    private_key = ed25519.Ed25519PrivateKey.generate()
    public_key = private_key.public_key()
    
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    
    return private_pem.decode('utf-8'), public_pem.decode('utf-8')

def sign_data(private_key_pem, data):
    """Sign data with a private key"""
    if isinstance(data, dict):
        data = json.dumps(data).encode('utf-8')
    elif isinstance(data, str):
        data = data.encode('utf-8')
    
    private_key = load_pem_private_key(
        private_key_pem.encode('utf-8'),
        password=None
    )
    
    signature = private_key.sign(data)
    return base64.b64encode(signature).decode('utf-8')

def verify_signature(public_key_pem, data, signature):
    """Verify a signature against data with a public key"""
    if isinstance(data, dict):
        data = json.dumps(data).encode('utf-8')
    elif isinstance(data, str):
        data = data.encode('utf-8')
    
    public_key = load_pem_public_key(public_key_pem.encode('utf-8'))
    signature_bytes = base64.b64decode(signature)
    
    try:
        public_key.verify(signature_bytes, data)
        return True
    except InvalidSignature:
        return False

def hash_data(data):
    """Create SHA-256 hash of data"""
    if isinstance(data, dict):
        data = json.dumps(data).encode('utf-8')
    elif isinstance(data, str):
        data = data.encode('utf-8')
    
    return hashlib.sha256(data).hexdigest()

def generate_credential_id():
    """Generate a unique credential ID"""
    return str(uuid.uuid4())

def compute_credential_hash(credential):
    """Compute hash of credential for blockchain storage"""
    cred_dict = {
        "uuid": credential.uuid,
        "issuer": credential.issuer_id,
        "student": credential.student_id,
        "timestamp": credential.issue_timestamp.isoformat(),
        "course_code": credential.course_code,
        "grade": credential.exam_grade,
        "credits": credential.ects_credits
    }
    return hash_data(cred_dict)

def create_proof_of_integrity(credential):
    """Create a proof of integrity for the credential"""
    # In a real app, this would use ZKP or BBS+ signatures
    # Here we just create a simplified hash
    cred_hash = compute_credential_hash(credential)
    return {
        "type": "IntegrityProof",
        "created": credential.issue_timestamp.isoformat() + "Z",
        "hash": cred_hash,
        "method": "SHA-256"
    }

def generate_challenge():
    """Generate a random challenge for authentication"""
    return base64.b64encode(os.urandom(32)).decode('utf-8')

def verify_challenge_response(challenge, response, public_key_pem):
    """Verify a challenge-response for authentication"""
    return verify_signature(public_key_pem, challenge, response)

def selective_disclosure(credential, fields_to_disclose):
    """Create a selective disclosure of a credential with only specified fields"""
    full_dict = credential.to_dict()
    disclosed_dict = {
        "metadati": {
            "versione": full_dict["metadati"]["versione"],
            "identificativoUUID": full_dict["metadati"]["identificativoUUID"],
            "timestampEmissione": full_dict["metadati"]["timestampEmissione"],
            "firma": full_dict["metadati"]["firma"]
        },
        "emittente": full_dict["emittente"],
        "soggetto": {
            "identificativoStudente": {
                "identificativoPseudonimo": full_dict["soggetto"]["identificativoStudente"]["identificativoPseudonimo"],
                "protezionePrivacy": "divulgazione_selettiva"
            }
        },
        "attributiAccademici": {}
    }
    
    # Add only the requested academic attributes
    for field in fields_to_disclose:
        if field in full_dict["attributiAccademici"]:
            disclosed_dict["attributiAccademici"][field] = full_dict["attributiAccademici"][field]
    
    return disclosed_dict

def generate_ocsp_response(credential_uuid, status, private_key_pem):
    """Generate a simplified OCSP response"""
    response_data = {
        "credential_uuid": credential_uuid,
        "status": status,
        "produced_at": datetime.utcnow().isoformat() + "Z",
        "this_update": datetime.utcnow().isoformat() + "Z",
        "next_update": (datetime.utcnow() + datetime.timedelta(hours=24)).isoformat() + "Z"
    }
    
    signature = sign_data(private_key_pem, response_data)
    response_data["signature"] = signature
    
    return response_data