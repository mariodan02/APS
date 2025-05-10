# services/revocation_service.py
import json
import hashlib
import fcntl
import time
import os
from datetime import datetime

class RevocationRegistryService:
    """
    Servizio per la gestione del registro distribuito delle revoche.
    Simula l'interazione con una blockchain o un ledger distribuito.
    """
    
    def __init__(self, registry_file=None):
        """
        Inizializza il servizio del registro di revoca.
        
        Args:
            registry_file: Percorso del file per il registro (per simulazione)
        """
        self.registry_file = registry_file or os.path.join(os.path.dirname(__file__), '../data/revocation_registry.json')
        self._ensure_registry_exists()
    
    def _ensure_registry_exists(self):
        """Assicura che il file del registro esista"""
        os.makedirs(os.path.dirname(self.registry_file), exist_ok=True)
        
        if not os.path.exists(self.registry_file):
            with open(self.registry_file, 'w') as f:
                json.dump({
                    "blocks": [self._create_genesis_block()],
                    "revoked_credentials": {}
                }, f, indent=2)
    
    def _create_genesis_block(self):
        """Crea il blocco iniziale del registro"""
        return {
            "index": 0,
            "timestamp": datetime.now().isoformat(),
            "data": {
                "message": "Genesis Block for Academic Credentials Revocation Registry"
            },
            "previous_hash": "0",
            "hash": "0000000000000000000000000000000000000000000000000000000000000000"
        }
    
    def _load_registry(self):
        """Carica il registro dal file"""
        os.makedirs(os.path.dirname(self.registry_file), exist_ok=True)
        
        try:
            with open(self.registry_file, 'r') as f:
                try:
                    fcntl.flock(f, fcntl.LOCK_SH)  # Shared lock for reading
                    registry = json.load(f)
                    return registry
                finally:
                    fcntl.flock(f, fcntl.LOCK_UN)  # Release lock
        except (FileNotFoundError, json.JSONDecodeError):
            registry = {
                "blocks": [self._create_genesis_block()],
                "revoked_credentials": {}
            }
            self._save_registry(registry)
            return registry

    def _save_registry(self, registry):
        """Salva il registro nel file"""
        os.makedirs(os.path.dirname(self.registry_file), exist_ok=True)
        
        with open(self.registry_file, 'w') as f:
            try:
                fcntl.flock(f, fcntl.LOCK_EX)  # Exclusive lock for writing
                json.dump(registry, f, indent=2)
            finally:
                fcntl.flock(f, fcntl.LOCK_UN)  # Release lock

    def _create_block(self, data, previous_block):
        """
        Crea un nuovo blocco nel registro.
        
        Args:
            data: Dati da inserire nel blocco
            previous_block: Blocco precedente
        
        Returns:
            dict: Nuovo blocco
        """
        block = {
            "index": previous_block["index"] + 1,
            "timestamp": datetime.now().isoformat(),
            "data": data,
            "previous_hash": previous_block["hash"]
        }
        
        # Calcola l'hash del blocco
        block_string = json.dumps(block, sort_keys=True).encode()
        block["hash"] = hashlib.sha256(block_string).hexdigest()
        
        return block
    
    def revoke_credential(self, credential_uuid, revocation_id, reason=None, revoker=None):
        """
        Registra la revoca di una credenziale nel ledger distribuito.
        
        Args:
            credential_uuid: UUID della credenziale da revocare
            revocation_id: ID univoco di revoca
            reason: Motivo della revoca
            revoker: Informazioni su chi ha eseguito la revoca
        
        Returns:
            dict: Informazioni sul blocco di revoca
        """
        registry = self._load_registry()
        
        # Controlla se la credenziale è già stata revocata
        if credential_uuid in registry["revoked_credentials"]:
            return {
                "success": False,
                "message": "Credenziale già revocata",
                "revocation_info": registry["revoked_credentials"][credential_uuid]
            }
        
        # Prepara i dati di revoca
        revocation_data = {
            "credential_uuid": credential_uuid,
            "revocation_id": revocation_id,
            "timestamp": datetime.now().isoformat(),
            "reason": reason,
            "revoker": revoker
        }
        
        # Crea un nuovo blocco per la revoca
        previous_block = registry["blocks"][-1]
        new_block = self._create_block(revocation_data, previous_block)
        
        # Aggiungi il blocco al registro
        registry["blocks"].append(new_block)
        
        # Aggiorna la lista delle credenziali revocate
        registry["revoked_credentials"][credential_uuid] = {
            "revocation_id": revocation_id,
            "block_index": new_block["index"],
            "block_hash": new_block["hash"],
            "timestamp": revocation_data["timestamp"],
            "reason": reason
        }
        
        # Salva il registro aggiornato
        self._save_registry(registry)
        
        return {
            "success": True,
            "message": "Credenziale revocata con successo",
            "block": new_block,
            "revocation_info": registry["revoked_credentials"][credential_uuid]
        }
    
    def check_revocation(self, credential_uuid):
        """
        Verifica se una credenziale è stata revocata.
        
        Args:
            credential_uuid: UUID della credenziale da verificare
        
        Returns:
            dict: Informazioni sulla revoca o None se non revocata
        """
        registry = self._load_registry()
        
        if credential_uuid in registry["revoked_credentials"]:
            return registry["revoked_credentials"][credential_uuid]
        
        return None
    
    def check_revocation_by_id(self, revocation_id):
        """
        Verifica la revoca tramite l'ID di revoca.
        
        Args:
            revocation_id: ID univoco di revoca
        
        Returns:
            dict: Informazioni sulla revoca o None se non trovata
        """
        registry = self._load_registry()
        
        # Cerca l'ID di revoca tra le credenziali revocate
        for uuid, info in registry["revoked_credentials"].items():
            if info["revocation_id"] == revocation_id:
                return {
                    "credential_uuid": uuid,
                    **info
                }
        
        return None
    
    def get_chain_status(self):
        """
        Ottiene lo stato attuale della catena.
        
        Returns:
            dict: Informazioni sulla catena
        """
        registry = self._load_registry()
        
        return {
            "chain_length": len(registry["blocks"]),
            "latest_block": registry["blocks"][-1],
            "revoked_count": len(registry["revoked_credentials"])
        }


# Esempio di endpoint per il registro distribuito
# In un'implementazione reale, questa sarebbe un'API REST o un interazione con nodi blockchain
from flask import Blueprint, request, jsonify

revocation_registry_bp = Blueprint('revocation_registry', __name__, url_prefix='/api/registry')

@revocation_registry_bp.route('/status', methods=['GET'])
def get_status():
    """Endpoint per ottenere lo stato del registro"""
    registry = RevocationRegistryService()
    return jsonify(registry.get_chain_status())

@revocation_registry_bp.route('/check/<uuid:credential_uuid>', methods=['GET'])
def check_credential(credential_uuid):
    """Endpoint per verificare lo stato di revoca di una credenziale"""
    registry = RevocationRegistryService()
    revocation_info = registry.check_revocation(str(credential_uuid))
    
    if revocation_info:
        return jsonify({
            "revoked": True,
            "revocation_info": revocation_info
        })
    
    return jsonify({
        "revoked": False
    })

@revocation_registry_bp.route('/webhook', methods=['POST'])
def revocation_webhook():
    """
    Webhook per ricevere aggiornamenti sulle revoche da altri nodi.
    In un sistema distribuito reale, questo sarebbe un endpoint per la sincronizzazione tra nodi.
    """
    data = request.json
    
    if not data or 'credential_uuid' not in data or 'revocation_id' not in data:
        return jsonify({"error": "Dati incompleti"}), 400
    
    registry = RevocationRegistryService()
    result = registry.revoke_credential(
        data['credential_uuid'],
        data['revocation_id'],
        data.get('reason'),
        data.get('revoker')
    )
    
    if result['success']:
        return jsonify({
            "message": "Revoca sincronizzata correttamente",
            "block": result['block']
        })
    
    return jsonify({
        "message": result['message'],
        "revocation_info": result['revocation_info']
    })