# file: x509_utils.py

import datetime
import re
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.backends import default_backend
import os

class X509CertificateManager:
    """
    Classe per la gestione dei certificati X.509v3 utilizzati nel sistema.
    Supporta la creazione, verifica e gestione dei certificati per università e CA.
    """
    
    def __init__(self):
        """
        Inizializza il gestore dei certificati X.509.
        """
        self.certs_directory = "certificates"
        os.makedirs(self.certs_directory, exist_ok=True)
    
    def generate_ca_certificate(self, common_name="Certificate Authority"):
        """
        Genera un certificato root per la Certificate Authority.
        
        Args:
            common_name: Nome della CA
            
        Returns:
            Percorsi dei file del certificato e della chiave privata
        """
        # Generazione della chiave privata
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=4096,
            backend=default_backend()
        )
        
        # Creazione del subject
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, "UE"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Erasmus Credentials System"),
            x509.NameAttribute(NameOID.COMMON_NAME, common_name)
        ])
        
        # Creazione del certificato
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
        ).sign(private_key, hashes.SHA256(), default_backend())
        
        # Salvataggio del certificato e della chiave
        cert_path = os.path.join(self.certs_directory, "ca_cert.pem")
        key_path = os.path.join(self.certs_directory, "ca_key.pem")
        
        with open(cert_path, "wb") as f:
            f.write(cert.public_bytes(serialization.Encoding.PEM))
            
        with open(key_path, "wb") as f:
            f.write(private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            ))
            
        return cert_path, key_path
        
    def sanitize_dns_name(self, name):
        """
        Sanitizza un nome per uso come DNS eliminando i caratteri non-ASCII.
        
        Args:
            name: Nome da sanitizzare
            
        Returns:
            Nome sanitizzato per uso come DNS
        """
        # Rimuove caratteri non-ASCII e sostituisce spazi con niente
        return re.sub(r'[^\x00-\x7F]', '', name.lower().replace(' ', ''))
        
    def generate_university_certificate(self, university_name, country, ca_cert_path, ca_key_path):
        """
        Genera un certificato per un'università firmato dalla CA.
        
        Args:
            university_name: Nome dell'università
            country: Paese dell'università
            ca_cert_path: Percorso del certificato CA
            ca_key_path: Percorso della chiave privata CA
            
        Returns:
            Percorsi dei file del certificato e della chiave privata
        """

        # Mappa dei paesi ai codici ISO a due lettere
        country_codes = {
            "Italia": "IT",
            "Francia": "FR",
            "Germania": "DE",
            "Spagna": "ES",
            "Regno Unito": "GB",
            "UE": "EU",  # Non è un codice ISO standard ma potrebbe essere usato per la CA
            # Aggiungi altri paesi secondo necessità
        }
        
        # Converti il nome del paese in codice ISO
        iso_country = country_codes.get(country, "EU")  # Default a EU se non trovato

        # Caricamento del certificato e della chiave della CA
        with open(ca_cert_path, "rb") as f:
            ca_cert = x509.load_pem_x509_certificate(f.read(), default_backend())
            
        with open(ca_key_path, "rb") as f:
            ca_key = serialization.load_pem_private_key(f.read(), password=None, backend=default_backend())
        
        # Generazione chiave privata università
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        
        # Creazione del subject per l'università
        subject = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, iso_country),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Erasmus Network"),
            x509.NameAttribute(NameOID.COMMON_NAME, university_name)
        ])
        
        # Sanitizzazione del nome università per DNS
        safe_dns_name = self.sanitize_dns_name(university_name) + ".edu"
        
        # Creazione del certificato
        cert = x509.CertificateBuilder().subject_name(
            subject
        ).issuer_name(
            ca_cert.issuer
        ).public_key(
            private_key.public_key()
        ).serial_number(
            x509.random_serial_number()
        ).not_valid_before(
            datetime.datetime.utcnow()
        ).not_valid_after(
            datetime.datetime.utcnow() + datetime.timedelta(days=365)
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
        ).add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_cert.public_key()),
            critical=False
        ).add_extension(
            x509.SubjectAlternativeName([
                x509.DNSName(safe_dns_name)
            ]),
            critical=False
        ).add_extension(
            x509.AuthorityInformationAccess([
                x509.AccessDescription(
                    x509.oid.AuthorityInformationAccessOID.OCSP,
                    x509.UniformResourceIdentifier("https://ocsp.ca.edu/")
                )
            ]),
            critical=False
        ).sign(ca_key, hashes.SHA256(), default_backend())
        
        # Salvataggio del certificato e della chiave
        safe_name = university_name.lower().replace(' ', '_')
        cert_path = os.path.join(self.certs_directory, f"{safe_name}_cert.pem")
        key_path = os.path.join(self.certs_directory, f"{safe_name}_key.pem")
        
        with open(cert_path, "wb") as f:
            f.write(cert.public_bytes(serialization.Encoding.PEM))
            
        with open(key_path, "wb") as f:
            f.write(private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            ))
            
        return cert_path, key_path
        
    def verify_certificate_chain(self, cert_path, ca_cert_path):
        """
        Verifica la catena di certificati.
        
        Args:
            cert_path: Percorso del certificato da verificare
            ca_cert_path: Percorso del certificato CA
            
        Returns:
            True se la verifica ha successo, False altrimenti
        """
        try:
            # Caricamento dei certificati
            with open(cert_path, "rb") as f:
                cert = x509.load_pem_x509_certificate(f.read(), default_backend())
                
            with open(ca_cert_path, "rb") as f:
                ca_cert = x509.load_pem_x509_certificate(f.read(), default_backend())
                
            # Verifica della firma
            ca_public_key = ca_cert.public_key()
            
            # In una implementazione reale, si verificherebbe anche:
            # - La validità temporale
            # - La revoca tramite CRL o OCSP
            # - Altre estensioni critiche
            
            try:
                ca_public_key.verify(
                    cert.signature,
                    cert.tbs_certificate_bytes,
                    padding.PKCS1v15(),
                    cert.signature_hash_algorithm
                )
                return True
            except Exception:
                return False
                
        except Exception as e:
            print(f"Errore durante la verifica del certificato: {e}")
            return False