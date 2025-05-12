import hashlib
import json
import time
import logging
from datetime import datetime
from models import db, BlockchainBlock

class SimpleBlockchain:
    """
    Implementa una blockchain semplificata per la gestione delle credenziali accademiche.
    Integra la funzionalità TLS per comunicazioni sicure tra nodi.
    """
    
    def __init__(self):
        """Inizializza la blockchain e configura il logging"""
        # Verifica se la blockchain esiste, se non esiste la inizializza
        self.logger = logging.getLogger("SimpleBlockchain")
        self.use_tls = True  # Configura per usare TLS
        self.tls_manager = None  # Sarà inizializzato on-demand
        
        # Controlla se ci sono blocchi esistenti
        if BlockchainBlock.query.count() == 0:
            self.add_genesis_block()
    
    def init_tls(self, cert_path=None, key_path=None, ca_path=None):
        """
        Inizializza il TLS Manager per comunicazioni sicure tra nodi blockchain.
        
        Args:
            cert_path: Percorso del certificato
            key_path: Percorso della chiave privata
            ca_path: Percorso del certificato CA
            
        Returns:
            Istanza TLSManager inizializzata
        """
        from tls import TLSManager
        
        if not self.tls_manager and self.use_tls:
            self.logger.info("Inizializzazione TLS per la blockchain")
            self.tls_manager = TLSManager(cert_path, key_path, ca_path)
        return self.tls_manager
    
    def add_genesis_block(self):
        """Crea il blocco genesi per la blockchain"""
        self.logger.info("Creazione del blocco genesi")
        genesis_block = BlockchainBlock(
            hash="0000genesis0000",
            previous_hash="0",
            timestamp=datetime.utcnow(),
            data=json.dumps({"message": "Blocco genesi per il sistema di credenziali accademiche"}),
            nonce=0
        )
        db.session.add(genesis_block)
        db.session.commit()
        return genesis_block
    
    def calculate_hash(self, index, previous_hash, timestamp, data, nonce):
        """
        Calcola l'hash per un blocco.
        
        Args:
            index: Indice del blocco
            previous_hash: Hash del blocco precedente
            timestamp: Timestamp del blocco
            data: Dati contenuti nel blocco
            nonce: Nonce per proof-of-work
            
        Returns:
            Hash SHA-256 del blocco
        """
        value = str(index) + str(previous_hash) + str(timestamp) + str(data) + str(nonce)
        return hashlib.sha256(value.encode('utf-8')).hexdigest()
    
    def get_last_block(self):
        """
        Ottiene l'ultimo blocco nella blockchain.
        
        Returns:
            Oggetto BlockchainBlock dell'ultimo blocco
        """
        return BlockchainBlock.query.order_by(BlockchainBlock.id.desc()).first()
    
    def proof_of_work(self, index, previous_hash, timestamp, data):
        """
        Proof of work semplificato per la creazione del blocco (solo per simulazione).
        In una blockchain reale, questo sarebbe più complesso.
        
        Args:
            index: Indice del blocco
            previous_hash: Hash del blocco precedente
            timestamp: Timestamp del blocco
            data: Dati contenuti nel blocco
            
        Returns:
            Tupla (nonce, hash) dove nonce è il valore trovato e hash è l'hash valido
        """
        nonce = 0
        computed_hash = self.calculate_hash(index, previous_hash, timestamp, data, nonce)
        
        # In una blockchain reale, cercheremmo un hash con caratteristiche specifiche
        # Per questa simulazione, facciamo solo un lavoro minimo
        while not computed_hash.startswith('0'):
            nonce += 1
            computed_hash = self.calculate_hash(index, previous_hash, timestamp, data, nonce)
        
        return nonce, computed_hash
    
    def add_block(self, data):
        """
        Aggiunge un nuovo blocco alla blockchain.
        
        Args:
            data: Dati da includere nel blocco
            
        Returns:
            Oggetto BlockchainBlock del nuovo blocco
        """
        self.logger.info(f"Aggiunta di un nuovo blocco: {data.get('type', 'N/A')}")
        last_block = self.get_last_block()
        
        # Prepara i dati del nuovo blocco
        index = last_block.id + 1
        timestamp = datetime.utcnow()
        nonce, computed_hash = self.proof_of_work(index, last_block.hash, timestamp, data)
        
        # Crea e salva il nuovo blocco
        new_block = BlockchainBlock(
            hash=computed_hash,
            previous_hash=last_block.hash,
            timestamp=timestamp,
            data=json.dumps(data),
            nonce=nonce
        )
        
        db.session.add(new_block)
        db.session.commit()
        
        # Utilizza TLS per comunicare con gli altri nodi se configurato
        if self.use_tls and self.tls_manager:
            try:
                self.logger.info("Invio del blocco tramite TLS agli altri nodi")
                # In un sistema reale, qui ci sarebbe un loop per inviare il blocco a tutti i nodi
                # For esempio:
                # for node in self.nodes:
                #     self.tls_manager.connect_to_server(node.host, node.port)
                #     ... invia il nuovo blocco ...
            except Exception as e:
                self.logger.error(f"Errore nella comunicazione TLS: {e}")
        
        return new_block
    
    def is_valid(self):
        """
        Convalida l'integrità della blockchain.
        
        Returns:
            True se la blockchain è valida, False altrimenti
        """
        self.logger.info("Verifica dell'integrità della blockchain")
        blocks = BlockchainBlock.query.order_by(BlockchainBlock.id).all()
        
        for i in range(1, len(blocks)):
            current = blocks[i]
            previous = blocks[i-1]
            
            # Verifica se l'hash del blocco corrente è valido
            if current.previous_hash != previous.hash:
                self.logger.warning(f"Mancata corrispondenza hash precedente nel blocco {current.id}")
                return False
            
            # Verifica se l'hash è calcolato correttamente
            calculated_hash = self.calculate_hash(
                current.id, 
                current.previous_hash, 
                current.timestamp, 
                current.data, 
                current.nonce
            )
            
            if current.hash != calculated_hash:
                self.logger.warning(f"Hash non valido nel blocco {current.id}")
                return False
        
        self.logger.info("Blockchain valida")
        return True
    
    def add_credential(self, credential):
        """
        Aggiunge una credenziale alla blockchain.
        
        Args:
            credential: Oggetto Credential da aggiungere
            
        Returns:
            Hash del blocco che contiene la credenziale
        """
        self.logger.info(f"Registrazione credenziale {credential.uuid} nella blockchain")
        data = {
            "type": "credential_issuance",
            "credential_uuid": credential.uuid,
            "issuer_id": credential.issuer_id,
            "student_id": credential.student_id,
            "timestamp": credential.issue_timestamp.isoformat(),
            "status": "active"
        }
        
        # Utilizza TLS per la comunicazione se configurato
        if self.use_tls and self.tls_manager:
            self.logger.info(f"Utilizzo TLS per la registrazione della credenziale {credential.uuid}")
            # In un sistema reale, qui ci sarebbe una comunicazione TLS con i validatori
        
        block = self.add_block(data)
        return block.hash
    
    def revoke_credential(self, credential_uuid, reason, revoker_id):
        """
        Aggiunge un record di revoca alla blockchain.
        
        Args:
            credential_uuid: UUID della credenziale da revocare
            reason: Motivo della revoca
            revoker_id: ID dell'utente che revoca la credenziale
            
        Returns:
            Hash del blocco che contiene la revoca
        """
        self.logger.info(f"Revoca della credenziale {credential_uuid} nella blockchain")
        data = {
            "type": "credential_revocation",
            "credential_uuid": credential_uuid,
            "reason": reason,
            "revoker_id": revoker_id,
            "timestamp": datetime.utcnow().isoformat()
        }
        
        # Utilizza TLS per la comunicazione se configurato
        if self.use_tls and self.tls_manager:
            self.logger.info(f"Utilizzo TLS per la revoca della credenziale {credential_uuid}")
            # In un sistema reale, qui ci sarebbe una comunicazione TLS con i validatori
            # e potrebbe essere implementato lo scenario di revoca completo
        
        block = self.add_block(data)
        return block.hash
    
    def verify_credential(self, credential_uuid):
        """
        Verifica se una credenziale è valida o revocata.
        
        Args:
            credential_uuid: UUID della credenziale da verificare
            
        Returns:
            Stato della credenziale ("good", "revoked", o "unknown")
        """
        self.logger.info(f"Verifica della credenziale {credential_uuid}")
        blocks = BlockchainBlock.query.order_by(BlockchainBlock.id).all()
        
        issuance_block = None
        revocation_block = None
        
        for block in blocks:
            try:
                block_data = json.loads(block.data)
                
                if 'credential_uuid' in block_data and block_data['credential_uuid'] == credential_uuid:
                    if block_data['type'] == 'credential_issuance':
                        issuance_block = block
                    elif block_data['type'] == 'credential_revocation':
                        revocation_block = block
            except:
                continue
        
        # Utilizza TLS per la comunicazione se configurato
        if self.use_tls and self.tls_manager:
            self.logger.info(f"Utilizzo TLS per la verifica della credenziale {credential_uuid}")
            # In un sistema reale, qui ci sarebbe una comunicazione TLS con i validatori
        
        if not issuance_block:
            return "unknown"  # Credenziale non trovata
        
        if revocation_block:
            return "revoked"  # Credenziale revocata
            
        return "good"  # Credenziale valida