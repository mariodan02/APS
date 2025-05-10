# services/crypto_service.py
from Crypto.PublicKey import ECC
from Crypto.Signature import DSS
from Crypto.Hash import SHA256
import base64
import json
import uuid

class CryptoService:
    @staticmethod
    def generate_key_pair():
        """Genera una coppia di chiavi per firme Ed25519"""
        # In produzione si utilizzerebbe una vera libreria EdDSA
        # Per questo esempio usiamo ECC con curve P-256
        key = ECC.generate(curve='P-256')
        private_key = key.export_key(format='PEM')
        public_key = key.public_key().export_key(format='PEM')
        
        return {
            'private_key': private_key,
            'public_key': public_key
        }
    
    @staticmethod
    def sign_credential(credential_data, private_key_pem):
        """Firma i dati della credenziale con la chiave privata dell'emittente"""
        try:
            # Converti i dati in JSON e poi in bytes
            data_bytes = json.dumps(credential_data).encode('utf-8')
            
            # Crea l'hash dei dati
            h = SHA256.new(data_bytes)
            
            # Carica la chiave privata e firma
            key = ECC.import_key(private_key_pem)
            signer = DSS.new(key, 'fips-186-3')
            signature = signer.sign(h)
            
            # Codifica la firma in base64
            return base64.b64encode(signature).decode('utf-8')
        except Exception as e:
            print(f"Errore durante la firma: {str(e)}")
            return None
    
    @staticmethod
    def verify_signature(data, signature, public_key_pem):
        """Verifica la firma di una credenziale"""
        try:
            # Converti la firma da base64 a bytes
            signature_bytes = base64.b64decode(signature)
            
            # Converti i dati in JSON e poi in bytes
            data_bytes = json.dumps(data).encode('utf-8')
            
            # Crea l'hash dei dati
            h = SHA256.new(data_bytes)
            
            # Carica la chiave pubblica e verifica
            key = ECC.import_key(public_key_pem)
            verifier = DSS.new(key, 'fips-186-3')
            
            try:
                verifier.verify(h, signature_bytes)
                return True
            except ValueError:
                return False
        except Exception as e:
            print(f"Errore durante la verifica: {str(e)}")
            return False
    
    @staticmethod
    def generate_credential_id():
        """Genera un ID univoco per una credenziale"""
        return str(uuid.uuid4())
