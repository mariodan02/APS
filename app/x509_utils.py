#!/usr/bin/env python3
"""
Utility per la gestione dei certificati X.509
"""
import os
import datetime
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import (
    Encoding, PrivateFormat, PublicFormat, NoEncryption,
    load_pem_private_key, load_pem_public_key
)

def generate_ca_certificate(common_name="Academic Credentials CA"):
    """Genera un certificato root per la CA"""
    # Genera una chiave privata
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )

    # Informazioni sul soggetto e sull'emittente del certificato
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "IT"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Campania"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, "Salerno"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Academic Credentials System"),
        x509.NameAttribute(NameOID.COMMON_NAME, common_name),
    ])

    # Crea il certificato
    cert = x509.CertificateBuilder().subject_name(
        subject
    ).issuer_name(
        issuer
    ).public_key(
        private_key.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.datetime.utcnow()
    ).not_valid_after(
        # Valido per 10 anni
        datetime.datetime.utcnow() + datetime.timedelta(days=3650)
    ).add_extension(
        x509.BasicConstraints(ca=True, path_length=None), critical=True
    ).add_extension(
        x509.KeyUsage(
            digital_signature=True,
            content_commitment=False,
            key_encipherment=True,
            data_encipherment=False,
            key_agreement=False,
            key_cert_sign=True,
            crl_sign=True,
            encipher_only=False,
            decipher_only=False
        ), critical=True
    ).sign(private_key, hashes.SHA256())

    # Salva il certificato e la chiave privata
    cert_pem = cert.public_bytes(Encoding.PEM)
    private_key_pem = private_key.private_bytes(
        encoding=Encoding.PEM,
        format=PrivateFormat.PKCS8,
        encryption_algorithm=NoEncryption()
    )

    return cert_pem, private_key_pem

def generate_university_certificate(ca_cert_pem, ca_key_pem, university_name, country="IT", 
                                  state="Campania", locality="Salerno"):
    """Genera un certificato per un'università firmato dalla CA"""
    # Carica il certificato e la chiave della CA
    ca_cert = x509.load_pem_x509_certificate(ca_cert_pem)
    ca_key = load_pem_private_key(ca_key_pem, password=None)

    # Genera una nuova chiave per l'università
    univ_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )

    # Crea il certificato dell'università
    subject = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, country),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, state),
        x509.NameAttribute(NameOID.LOCALITY_NAME, locality),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, university_name),
        x509.NameAttribute(NameOID.COMMON_NAME, f"{university_name} Certificate"),
    ])

    cert = x509.CertificateBuilder().subject_name(
        subject
    ).issuer_name(
        ca_cert.subject
    ).public_key(
        univ_key.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.datetime.utcnow()
    ).not_valid_after(
        # Valido per 5 anni
        datetime.datetime.utcnow() + datetime.timedelta(days=1825)
    ).add_extension(
        x509.BasicConstraints(ca=False, path_length=None), critical=True
    ).add_extension(
        x509.KeyUsage(
            digital_signature=True,
            content_commitment=True,
            key_encipherment=True,
            data_encipherment=False,
            key_agreement=False,
            key_cert_sign=False,
            crl_sign=False,
            encipher_only=False,
            decipher_only=False
        ), critical=True
    ).sign(ca_key, hashes.SHA256())

    # Salva il certificato e la chiave privata
    cert_pem = cert.public_bytes(Encoding.PEM)
    private_key_pem = univ_key.private_bytes(
        encoding=Encoding.PEM,
        format=PrivateFormat.PKCS8,
        encryption_algorithm=NoEncryption()
    )

    return cert_pem, private_key_pem

def verify_certificate_chain(cert_pem, ca_cert_pem):
    """Verifica che un certificato sia firmato dalla CA specificata"""
    cert = x509.load_pem_x509_certificate(cert_pem)
    ca_cert = x509.load_pem_x509_certificate(ca_cert_pem)
    
    # Ottiene la chiave pubblica dalla CA
    public_key = ca_cert.public_key()
    
    try:
        # Verifica la firma
        public_key.verify(
            cert.signature,
            cert.tbs_certificate_bytes,
            padding.PKCS1v15(),
            cert.signature_hash_algorithm,
        )
        return True
    except Exception:
        return False

def save_certificate(cert_pem, filename):
    """Salva un certificato su file"""
    with open(filename, 'wb') as f:
        f.write(cert_pem)

def save_private_key(key_pem, filename):
    """Salva una chiave privata su file"""
    with open(filename, 'wb') as f:
        f.write(key_pem)

def load_certificate(filename):
    """Carica un certificato da file"""
    with open(filename, 'rb') as f:
        return f.read()

def load_private_key(filename):
    """Carica una chiave privata da file"""
    with open(filename, 'rb') as f:
        return f.read()

def extract_public_key(cert_pem):
    """Estrae la chiave pubblica da un certificato X.509"""
    cert = x509.load_pem_x509_certificate(cert_pem)
    return cert.public_key().public_bytes(
        encoding=Encoding.PEM,
        format=PublicFormat.SubjectPublicKeyInfo
    )

def extract_common_name(cert_pem):
    """Estrae il common name da un certificato X.509"""
    cert = x509.load_pem_x509_certificate(cert_pem)
    return cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value