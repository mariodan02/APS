#!/usr/bin/env python3
"""
Implementazione della blockchain basata su Ethereum per la gestione
delle credenziali accademiche utilizzando Ganache
"""
import time
import json
import os
from typing import Dict, List, Any, Optional
from web3 import Web3
from web3.middleware import geth_poa_middleware

class Blockchain:
    """Implementazione della blockchain basata su Ethereum"""
    def __init__(self, ganache_url="http://127.0.0.1:7545", contract_address=None):
        # Connessione alla blockchain Ethereum (Ganache)
        self.web3 = Web3(Web3.HTTPProvider(ganache_url))
        
        # Aggiungi middleware per supportare Proof of Authority se necessario
        self.web3.middleware_onion.inject(geth_poa_middleware, layer=0)
        
        if not self.web3.is_connected():
            raise ConnectionError("Impossibile connettersi a Ganache. Assicurati che sia in esecuzione.")
            
        # Imposta l'indirizzo del contratto
        self.contract_address = contract_address
        
        # Inizializza il contratto
        if contract_address:
            self.contract = self._load_contract(contract_address)
        else:
            # Se non è fornito un indirizzo, è necessario distribuire il contratto
            print("Indirizzo del contratto non fornito. È necessario distribuire il contratto.")
            self.contract = None
    
    def _load_contract(self, contract_address):
        """Carica il contratto dall'indirizzo fornito"""
        # Carica l'ABI del contratto
        contract_abi_path = os.path.join(os.path.dirname(__file__), "../contracts/AcademicCredentials.json")
        with open(contract_abi_path) as f:
            contract_json = json.load(f)
            contract_abi = contract_json['abi']
        
        return self.web3.eth.contract(address=contract_address, abi=contract_abi)
    
    def deploy_contract(self, private_key):
        """Distribuisce il contratto sulla blockchain"""
        # Carica l'ABI e il bytecode del contratto
        contract_abi_path = os.path.join(os.path.dirname(__file__), "../contracts/AcademicCredentials.json")
        with open(contract_abi_path) as f:
            contract_json = json.load(f)
            contract_abi = contract_json['abi']
            contract_bytecode = contract_json['bytecode']
        
        # Account che distribuirà il contratto
        account = self.web3.eth.account.from_key(private_key)
        address = account.address
        
        # Crea l'istanza del contratto
        contract_instance = self.web3.eth.contract(abi=contract_abi, bytecode=contract_bytecode)
        
        # Stima del gas
        gas_estimate = contract_instance.constructor().estimate_gas({'from': address})
        
        # Prepara la transazione
        transaction = {
            'from': address,
            'gas': gas_estimate,
            'gasPrice': self.web3.to_wei('50', 'gwei'),
            'nonce': self.web3.eth.get_transaction_count(address)
        }
        
        # Costruisce la transazione per il deploy del contratto
        txn = contract_instance.constructor().build_transaction(transaction)
        
        # Firma la transazione
        signed_txn = account.sign_transaction(txn)
        
        # Invia la transazione
        txn_hash = self.web3.eth.send_raw_transaction(signed_txn.rawTransaction)
        
        # Attendi la conferma
        txn_receipt = self.web3.eth.wait_for_transaction_receipt(txn_hash)
        
        # Aggiorna l'indirizzo e l'istanza del contratto
        self.contract_address = txn_receipt.contractAddress
        self.contract = self.web3.eth.contract(address=self.contract_address, abi=contract_abi)
        
        return self.contract_address
    
    def add_credential(self, credential_id: str, student_id: str, issuer_id: str, 
                      merkle_root: str, private_key: str) -> bool:
        """Aggiunge una nuova credenziale alla blockchain"""
        if not self.contract:
            raise ValueError("Contratto non inizializzato")
            
        # Account che effettuerà la transazione
        account = self.web3.eth.account.from_key(private_key)
        address = account.address
        
        # Prepara la transazione
        transaction = {
            'from': address,
            'gas': 200000,
            'gasPrice': self.web3.to_wei('50', 'gwei'),
            'nonce': self.web3.eth.get_transaction_count(address)
        }
        
        # Crea la transazione
        txn = self.contract.functions.issueCredential(
            credential_id, student_id, issuer_id, merkle_root
        ).build_transaction(transaction)
        
        # Firma la transazione
        signed_txn = account.sign_transaction(txn)
        
        # Invia la transazione
        txn_hash = self.web3.eth.send_raw_transaction(signed_txn.rawTransaction)
        
        # Attendi la conferma
        txn_receipt = self.web3.eth.wait_for_transaction_receipt(txn_hash)
        
        return txn_receipt.status == 1
    
    def revoke_credential(self, credential_id: str, issuer_id: str, reason: str, private_key: str) -> bool:
        """Revoca una credenziale esistente"""
        if not self.contract:
            raise ValueError("Contratto non inizializzato")
            
        # Account che effettuerà la transazione
        account = self.web3.eth.account.from_key(private_key)
        address = account.address
        
        # Prepara la transazione
        transaction = {
            'from': address,
            'gas': 200000,
            'gasPrice': self.web3.to_wei('50', 'gwei'),
            'nonce': self.web3.eth.get_transaction_count(address)
        }
        
        # Crea la transazione
        txn = self.contract.functions.revokeCredential(
            credential_id, issuer_id, reason
        ).build_transaction(transaction)
        
        # Firma la transazione
        signed_txn = account.sign_transaction(txn)
        
        # Invia la transazione
        txn_hash = self.web3.eth.send_raw_transaction(signed_txn.rawTransaction)
        
        # Attendi la conferma
        txn_receipt = self.web3.eth.wait_for_transaction_receipt(txn_hash)
        
        return txn_receipt.status == 1
    
    def get_credential_status(self, credential_id: str) -> Optional[Dict[str, Any]]:
        """Restituisce lo stato attuale di una credenziale"""
        if not self.contract:
            raise ValueError("Contratto non inizializzato")
            
        # Chiama la funzione getCredentialStatus
        result = self.contract.functions.getCredentialStatus(credential_id).call()
        
        # Se la credenziale non esiste, return None
        if not result[0]:  # Se l'ID è vuoto
            return None
            
        # Formatta il risultato
        return {
            "credential_id": result[0],
            "student_id": result[1],
            "issuer_id": result[2],
            "status": result[3],
            "merkle_root": result[4],
            "reason": result[5],
            "timestamp": result[6],
            "revocation_timestamp": result[7]
        }