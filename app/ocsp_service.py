#!/usr/bin/env python3
"""
Implementazione di un semplice servizio di stato dei certificati online (OCSP)
"""
import time
import json
import sqlite3
from typing import Dict, Any, Optional, List

class OCSPService:
    """
    Servizio per la verifica dello stato delle credenziali
    Implementa una versione semplificata dell'Online Certificate Status Protocol
    """
    def __init__(self, db_path="./instance/credentials.db"):
        self.db_path = db_path
        self._init_db()
    
    def _init_db(self):
        """Inizializza il database"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Crea tabella per lo stato delle credenziali
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS credential_status (
            credential_id TEXT PRIMARY KEY,
            issuer_id TEXT NOT NULL,
            status TEXT NOT NULL,
            reason TEXT,
            timestamp INTEGER NOT NULL,
            revocation_timestamp INTEGER
        )
        ''')
        
        # Crea indice per le query rapide
        cursor.execute('''
        CREATE INDEX IF NOT EXISTS idx_issuer_id ON credential_status(issuer_id)
        ''')
        
        conn.commit()
        conn.close()
    
    def add_credential(self, credential_id: str, issuer_id: str) -> bool:
        """Aggiunge una nuova credenziale con stato 'valid'"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('''
            INSERT INTO credential_status 
            (credential_id, issuer_id, status, timestamp) 
            VALUES (?, ?, ?, ?)
            ''', (credential_id, issuer_id, 'valid', int(time.time())))
            
            conn.commit()
            conn.close()
            return True
        except Exception as e:
            print(f"Errore nell'aggiunta della credenziale: {e}")
            return False
    
    def revoke_credential(self, credential_id: str, issuer_id: str, reason: str) -> bool:
        """Revoca una credenziale esistente"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # Verifica che la credenziale esista e appartenga all'emittente
            cursor.execute('''
            SELECT * FROM credential_status 
            WHERE credential_id = ? AND issuer_id = ?
            ''', (credential_id, issuer_id))
            
            result = cursor.fetchone()
            if not result:
                conn.close()
                return False
            
            # Aggiorna lo stato della credenziale
            cursor.execute('''
            UPDATE credential_status 
            SET status = ?, reason = ?, revocation_timestamp = ? 
            WHERE credential_id = ?
            ''', ('revoked', reason, int(time.time()), credential_id))
            
            conn.commit()
            conn.close()
            return True
        except Exception as e:
            print(f"Errore nella revoca della credenziale: {e}")
            return False
    
    def check_credential_status(self, credential_id: str) -> Dict[str, Any]:
        """Verifica lo stato di una credenziale"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('''
            SELECT * FROM credential_status 
            WHERE credential_id = ?
            ''', (credential_id,))
            
            result = cursor.fetchone()
            conn.close()
            
            if not result:
                return {"status": "unknown"}
            
            if len(result) >= 6:
                return {
                    "credential_id": result[0],
                    "issuer_id": result[1],
                    "status": result[2],
                    "reason": result[3],
                    "timestamp": result[4],
                    "revocation_timestamp": result[5]
                }
            else:
                return {
                    "credential_id": result[0],
                    "issuer_id": result[1],
                    "status": result[2],
                    "timestamp": result[4]
                }
        except Exception as e:
            print(f"Errore nella verifica dello stato della credenziale: {e}")
            return {"status": "error", "message": str(e)}
    
    def get_issuer_credentials(self, issuer_id: str) -> List[Dict[str, Any]]:
        """Restituisce tutte le credenziali emesse da un emittente"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('''
            SELECT * FROM credential_status 
            WHERE issuer_id = ?
            ORDER BY timestamp DESC
            ''', (issuer_id,))
            
            results = cursor.fetchall()
            conn.close()
            
            credentials = []
            for result in results:
                if len(result) >= 6:
                    credentials.append({
                        "credential_id": result[0],
                        "issuer_id": result[1],
                        "status": result[2],
                        "reason": result[3],
                        "timestamp": result[4],
                        "revocation_timestamp": result[5]
                    })
                else:
                    credentials.append({
                        "credential_id": result[0],
                        "issuer_id": result[1],
                        "status": result[2],
                        "timestamp": result[4]
                    })
            
            return credentials
        except Exception as e:
            print(f"Errore nel recupero delle credenziali dell'emittente: {e}")
            return []