#!/usr/bin/env python3
"""
Utility crittografiche per il sistema di credenziali accademiche
"""
import os
import base64
import hashlib
import json
from cryptography.fernet import Fernet, MultiFernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.serialization import (
    Encoding, PrivateFormat, PublicFormat, NoEncryption,
    load_pem_private_key, load_pem_public_key
)

def generate_key_pair():
    """Genera una coppia di chiavi RSA per la firma"""
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )
    public_key = private_key.public_key()
    
    # Converti le chiavi in formato PEM
    private_key_pem = private_key.private_bytes(
        encoding=Encoding.PEM,
        format=PrivateFormat.PKCS8,
        encryption_algorithm=NoEncryption()
    )
    public_key_pem = public_key.public_bytes(
        encoding=Encoding.PEM,
        format=PublicFormat.SubjectPublicKeyInfo
    )
    
    return private_key_pem, public_key_pem

def generate_fernet_key():
    """Genera una chiave Fernet per la cifratura simmetrica"""
    return Fernet.generate_key()

def create_multifernet(keys):
    """Crea un MultiFernet con le chiavi fornite"""
    fernet_keys = [Fernet(key) for key in keys]
    return MultiFernet(fernet_keys)

def encrypt_data(data, key):
    """Cifra i dati con Fernet"""
    if isinstance(data, dict) or isinstance(data, list):
        data = json.dumps(data).encode()
    elif isinstance(data, str):
        data = data.encode()
        
    f = Fernet(key)
    return f.encrypt(data)

def decrypt_data(encrypted_data, key):
    """Decifra i dati con Fernet"""
    f = Fernet(key)
    decrypted = f.decrypt(encrypted_data)
    
    try:
        # Prova a interpretare come JSON
        return json.loads(decrypted)
    except:
        # Altrimenti restituisci come stringa
        return decrypted.decode()

def hash_data(data):
    """Calcola l'hash SHA-256 dei dati"""
    if isinstance(data, dict) or isinstance(data, list):
        data = json.dumps(data, sort_keys=True).encode()
    elif isinstance(data, str):
        data = data.encode()
        
    return hashlib.sha256(data).hexdigest()

def sign_data(data, private_key_pem):
    """Firma i dati con la chiave privata RSA"""
    if isinstance(data, dict) or isinstance(data, list):
        data = json.dumps(data, sort_keys=True).encode()
    elif isinstance(data, str):
        data = data.encode()
    
    private_key = load_pem_private_key(private_key_pem, password=None)
    
    signature = private_key.sign(
        data,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    
    return base64.b64encode(signature).decode()

def verify_signature(data, signature, public_key_pem):
    """Verifica la firma con la chiave pubblica RSA"""
    if isinstance(data, dict) or isinstance(data, list):
        data = json.dumps(data, sort_keys=True).encode()
    elif isinstance(data, str):
        data = data.encode()
        
    public_key = load_pem_public_key(public_key_pem)
    signature_bytes = base64.b64decode(signature)
    
    try:
        public_key.verify(
            signature_bytes,
            data,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except Exception:
        return False