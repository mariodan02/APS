#!/usr/bin/env python3
"""
Implementazione semplificata di una blockchain per la gestione
delle credenziali accademiche
"""
import time
import json
import hashlib
from typing import Dict, List, Any, Optional

class Block:
    """Rappresenta un blocco nella blockchain"""
    def __init__(self, index: int, timestamp: float, data: Dict[str, Any], 
                 previous_hash: str):
        self.index = index
        self.timestamp = timestamp
        self.data = data
        self.previous_hash = previous_hash
        self.hash = self.calculate_hash()
        
    def calculate_hash(self) -> str:
        """Calcola l'hash del blocco"""
        block_string = json.dumps({
            "index": self.index,
            "timestamp": self.timestamp,
            "data": self.data,
            "previous_hash": self.previous_hash
        }, sort_keys=True).encode()
        
        return hashlib.sha256(block_string).hexdigest()
    
    def to_dict(self) -> Dict[str, Any]:
        """Converte il blocco in un dizionario"""
        return {
            "index": self.index,
            "timestamp": self.timestamp,
            "data": self.data,
            "previous_hash": self.previous_hash,
            "hash": self.hash
        }

class Blockchain:
    """Implementazione semplificata di una blockchain"""
    def __init__(self):
        # Inizializza la catena con il blocco genesi
        self.chain = [self._create_genesis_block()]
        self.credential_index = {}  # Indice per ricerca rapida: credential_id -> block_index
        
    def _create_genesis_block(self) -> Block:
        """Crea il blocco genesi"""
        return Block(0, time.time(), {"message": "Genesis Block"}, "0")
    
    def get_latest_block(self) -> Block:
        """Restituisce l'ultimo blocco della catena"""
        return self.chain[-1]
    
    def add_block(self, data: Dict[str, Any]) -> Block:
        """Aggiunge un nuovo blocco alla catena"""
        previous_block = self.get_latest_block()
        new_index = previous_block.index + 1
        new_timestamp = time.time()
        new_block = Block(new_index, new_timestamp, data, previous_block.hash)
        
        self.chain.append(new_block)
        
        # Se il blocco contiene informazioni su una credenziale, aggiorna l'indice
        if "credential_id" in data:
            self.credential_index[data["credential_id"]] = new_index
            
        return new_block
    
    def is_chain_valid(self) -> bool:
        """Verifica l'integrità della blockchain"""
        for i in range(1, len(self.chain)):
            current_block = self.chain[i]
            previous_block = self.chain[i-1]
            
            # Verifica l'hash del blocco corrente
            if current_block.hash != current_block.calculate_hash():
                return False
                
            # Verifica il collegamento con il blocco precedente
            if current_block.previous_hash != previous_block.hash:
                return False
                
        return True
    
    def get_credential_status(self, credential_id: str) -> Optional[Dict[str, Any]]:
        """Restituisce lo stato attuale di una credenziale"""
        if credential_id not in self.credential_index:
            return None
            
        block_index = self.credential_index[credential_id]
        
        # Cerca il blocco più recente per questa credenziale
        latest_status = None
        for i in range(block_index, len(self.chain)):
            block = self.chain[i]
            if block.data.get("credential_id") == credential_id:
                latest_status = block.data
        
        return latest_status
    
    def add_credential(self, credential_id: str, issuer_id: str) -> Block:
        """Aggiunge una nuova credenziale alla blockchain"""
        data = {
            "type": "credential_issuance",
            "credential_id": credential_id,
            "issuer_id": issuer_id,
            "status": "valid",
            "timestamp": time.time()
        }
        return self.add_block(data)
    
    def revoke_credential(self, credential_id: str, issuer_id: str, reason: str) -> Optional[Block]:
        """Revoca una credenziale esistente"""
        # Verifica che la credenziale esista e appartenga all'emittente
        current_status = self.get_credential_status(credential_id)
        if not current_status or current_status.get("issuer_id") != issuer_id:
            return None
            
        data = {
            "type": "credential_revocation",
            "credential_id": credential_id,
            "issuer_id": issuer_id,
            "status": "revoked",
            "reason": reason,
            "timestamp": time.time()
        }
        return self.add_block(data)
    
    def to_json(self) -> str:
        """Converte l'intera blockchain in formato JSON"""
        return json.dumps([block.to_dict() for block in self.chain], indent=2)
    
    @classmethod
    def from_json(cls, json_data: str) -> 'Blockchain':
        """Crea una blockchain da una rappresentazione JSON"""
        blockchain = cls()
        blockchain.chain = []  # Svuota la catena
        
        blocks_data = json.loads(json_data)
        for block_data in blocks_data:
            block = Block(
                block_data["index"],
                block_data["timestamp"],
                block_data["data"],
                block_data["previous_hash"]
            )
            block.hash = block_data["hash"]
            blockchain.chain.append(block)
            
            # Ricostruisci l'indice delle credenziali
            if "credential_id" in block_data["data"]:
                blockchain.credential_index[block_data["data"]["credential_id"]] = block_data["index"]
                
        return blockchain
    
    def save_to_file(self, filename: str) -> None:
        """Salva la blockchain su file"""
        with open(filename, 'w') as f:
            f.write(self.to_json())
    
    @classmethod
    def load_from_file(cls, filename: str) -> 'Blockchain':
        """Carica la blockchain da file"""
        with open(filename, 'r') as f:
            return cls.from_json(f.read())