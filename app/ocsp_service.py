#!/usr/bin/env python3
"""
Implementazione di un servizio di stato dei certificati online (OCSP)
utilizzando la blockchain Ethereum
"""
import time
from typing import Dict, Any, Optional, List
from blockchain import Blockchain

class OCSPService:
    """
    Servizio per la verifica dello stato delle credenziali
    Implementa una versione di OCSP basata su blockchain Ethereum
    """
    def __init__(self, ganache_url="http://127.0.0.1:7545", contract_address=None):
        self.blockchain = Blockchain(ganache_url, contract_address)
        self.contract_address = contract_address
    
    def initialize(self, private_key):
        """Inizializza il servizio OCSP distribuendo il contratto se necessario"""
        if not self.contract_address:
            self.contract_address = self.blockchain.deploy_contract(private_key)
        return self.contract_address
    
    def add_credential(self, credential_id: str, student_id: str, issuer_id: str, 
                      merkle_root: str, private_key: str) -> bool:
        """Aggiunge una nuova credenziale con stato 'valid'"""
        return self.blockchain.add_credential(credential_id, student_id, issuer_id, 
                                            merkle_root, private_key)
    
    def revoke_credential(self, credential_id: str, issuer_id: str, reason: str, private_key: str) -> bool:
        """Revoca una credenziale esistente"""
        return self.blockchain.revoke_credential(credential_id, issuer_id, reason, private_key)
    
    def check_credential_status(self, credential_id: str) -> Dict[str, Any]:
        """Verifica lo stato di una credenziale"""
        result = self.blockchain.get_credential_status(credential_id)
        
        if not result:
            return {"status": "unknown"}
        
        return result
    
    def get_issuer_credentials(self, issuer_id: str) -> List[Dict[str, Any]]:
        """
        Questa funzionalità richiederebbe un metodo aggiuntivo nel contratto
        o il monitoraggio degli eventi. Per il momento ritorniamo una lista vuota.
        
        In una implementazione completa, si dovrebbero utilizzare gli eventi del contratto
        per tenere traccia di tutte le credenziali emesse da un emittente.
        """
        # Nota: questa è una versione semplificata
        print("Funzionalità get_issuer_credentials non supportata nella versione blockchain")
        return []