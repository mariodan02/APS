from flask import Blueprint, request, jsonify, current_app
from models import db, OCSPResponse, Credential, User
from datetime import datetime, timedelta
from crypto_utils import sign_data, verify_signature
import json
import logging
from ganache_blockchain import GanacheBlockchain  # Changed from SimpleBlockchain

# Configurazione logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)

# Inizializzazione blueprint e logger
ocsp = Blueprint('ocsp', __name__)
logger = logging.getLogger("OCPSService")

# Configurazione TLS
ocsp_tls = None

def init_ocsp_tls(ca_cert_path, ca_key_path):
    """
    Inizializza il TLS Manager per il servizio OCSP.
    
    Args:
        ca_cert_path: Percorso del certificato CA
        ca_key_path: Percorso della chiave privata CA
        
    Returns:
        Istanza TLSManager configurata per OCSP
    """
    global ocsp_tls
    from tls import TLSManager
    
    logger.info("Inizializzazione TLS per il servizio OCSP")
    ocsp_tls = TLSManager(ca_cert_path, ca_key_path, ca_cert_path)
    return ocsp_tls

@ocsp.route('/api/ocsp/check', methods=['POST'])
def check_credential():
    """
    Endpoint OCSP per verificare lo stato della credenziale.
    Implementa il flusso di verifica OCSP come descritto nel documento.
    
    Returns:
        Risposta OCSP in formato JSON
    """
    logger.info("Ricevuta richiesta OCSP")
    
    # Ottieni i dati della richiesta
    data = request.json
    if not data or 'credential_uuid' not in data:
        logger.warning("Richiesta OCSP mancante di credential_uuid")
        return jsonify({"error": "Missing credential_uuid"}), 400
    
    credential_uuid = data['credential_uuid']
    logger.info(f"Verifica OCSP per credenziale {credential_uuid}")
    
    # Utilizza TLS se configurato
    use_tls = current_app.config.get('USE_TLS', False)
    if use_tls and ocsp_tls:
        logger.info("Verifica OCSP con TLS abilitato")
        # In un'implementazione reale, qui ci sarebbe una comunicazione TLS sicura
    
    # Verifica se la credenziale esiste
    credential = Credential.query.filter_by(uuid=credential_uuid).first()
    if not credential:
        # Crea una risposta con stato sconosciuto
        logger.warning(f"Credenziale {credential_uuid} non trovata")
        return create_ocsp_response(credential_uuid, "unknown", None)
    
    # Verifica nella blockchain lo stato della credenziale
    blockchain = GanacheBlockchain(current_app.config.get('GANACHE_URL', 'http://127.0.0.1:7545'))
    
    # Configura TLS per blockchain se necessario
    if use_tls and ocsp_tls:
        blockchain.init_tls(
            ocsp_tls.cert_path,
            ocsp_tls.key_path,
            ocsp_tls.ca_path
        )
    
    status = blockchain.verify_credential(credential_uuid)
    logger.info(f"Stato della credenziale {credential_uuid}: {status}")
    
    # Crea e memorizza la risposta OCSP
    return create_ocsp_response(credential_uuid, status, credential)

def create_ocsp_response(credential_uuid, status, credential=None):
    """
    Crea una risposta OCSP per una credenziale.
    
    Args:
        credential_uuid: UUID della credenziale
        status: Stato della credenziale (good, revoked, unknown)
        credential: Oggetto Credential (opzionale)
        
    Returns:
        Risposta OCSP in formato JSON
    """
    logger.info(f"Creazione risposta OCSP per {credential_uuid}, stato: {status}")
    
    # Ottieni l'utente CA per la firma
    ca_user = User.query.filter_by(role='ca').first()
    if not ca_user:
        logger.error("CA non trovata nel sistema")
        return jsonify({"error": "CA non trovata"}), 500
    
    # Prepara i dati della risposta
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
    
    # Firma la risposta
    signature = sign_data(ca_user.private_key, json.dumps(response_data))
    
    # Aggiungi la firma alla risposta
    response_data["signature"] = {
        "algorithm": "Ed25519",
        "value": signature
    }
    
    # Memorizza la risposta OCSP nel database
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
    
    logger.info(f"Risposta OCSP per {credential_uuid} creata e memorizzata")
    return jsonify(response_data)

@ocsp.route('/api/ocsp/history/<credential_uuid>', methods=['GET'])
def get_ocsp_history(credential_uuid):
    """
    Ottiene la cronologia delle risposte OCSP per una credenziale.
    
    Args:
        credential_uuid: UUID della credenziale
        
    Returns:
        Cronologia delle risposte OCSP in formato JSON
    """
    logger.info(f"Richiesta cronologia OCSP per {credential_uuid}")
    
    # Utilizza TLS se configurato
    use_tls = current_app.config.get('USE_TLS', False)
    if use_tls and ocsp_tls:
        logger.info("Cronologia OCSP con TLS abilitato")
        # In un'implementazione reale, qui ci sarebbe una comunicazione TLS sicura
    
    responses = OCSPResponse.query.filter_by(credential_uuid=credential_uuid).order_by(OCSPResponse.produced_at.desc()).all()
    
    history = []
    for response in responses:
        history.append({
            "status": response.status,
            "produced_at": response.produced_at.isoformat() + "Z",
            "this_update": response.this_update.isoformat() + "Z",
            "next_update": response.next_update.isoformat() + "Z"
        })
    
    logger.info(f"Trovate {len(history)} risposte OCSP nella cronologia per {credential_uuid}")
    return jsonify({"credential_uuid": credential_uuid, "history": history})
