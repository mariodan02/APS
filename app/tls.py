#!/usr/bin/env python3
"""
Implementazione semplificata di un client e server TLS per il sistema di credenziali
"""
import os
import socket
import ssl
import json
import tempfile
from typing import Dict, Any, Tuple, Optional

def create_tls_context(cert_file, key_file, ca_cert=None, is_server=False):
    """
    Crea un contesto SSL/TLS
    
    Args:
        cert_file: Percorso del file del certificato
        key_file: Percorso del file della chiave privata
        ca_cert: Percorso del certificato CA (opzionale)
        is_server: True se è un server, False se è un client
        
    Returns:
        Un contesto SSL configurato
    """
    context = ssl.create_default_context(
        ssl.Purpose.CLIENT_AUTH if is_server else ssl.Purpose.SERVER_AUTH
    )
    
    # Usa TLS 1.3 per la massima sicurezza
    context.options |= ssl.OP_NO_TLSv1 | ssl.OP_NO_TLSv1_1 | ssl.OP_NO_TLSv1_2
    
    # Carica il certificato e la chiave
    context.load_cert_chain(certfile=cert_file, keyfile=key_file)
    
    # Se è specificato un certificato CA, lo usa per verificare l'altra parte
    if ca_cert:
        context.load_verify_locations(cafile=ca_cert)
        context.verify_mode = ssl.CERT_REQUIRED
    
    return context

class TLSConnection:
    """Gestisce una connessione TLS sicura"""
    def __init__(self, host, port, cert_file, key_file, ca_cert=None, is_server=False):
        self.host = host
        self.port = port
        self.cert_file = cert_file
        self.key_file = key_file
        self.ca_cert = ca_cert
        self.is_server = is_server
        self.ssl_context = create_tls_context(cert_file, key_file, ca_cert, is_server)
        self.connection = None
        
    def start_server(self):
        """Avvia un server TLS"""
        if not self.is_server:
            raise ValueError("Questa istanza è configurata come client")
            
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((self.host, self.port))
        sock.listen(5)
        
        print(f"Server in ascolto su {self.host}:{self.port}")
        
        while True:
            client_sock, addr = sock.accept()
            ssl_sock = self.ssl_context.wrap_socket(client_sock, server_side=True)
            yield TLSClientHandler(ssl_sock, addr)
    
    def connect(self):
        """Connette a un server TLS"""
        if self.is_server:
            raise ValueError("Questa istanza è configurata come server")
            
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.connection = self.ssl_context.wrap_socket(sock, server_hostname=self.host)
        self.connection.connect((self.host, self.port))
        
        # Verifica che il certificato del server sia valido
        if self.ca_cert:
            cert = self.connection.getpeercert()
            ssl.match_hostname(cert, self.host)
            
        return self.connection
    
    def send_data(self, data):
        """Invia dati sulla connessione"""
        if not self.connection:
            raise ValueError("Connessione non stabilita")
            
        # Converte i dati in JSON se necessario
        if isinstance(data, dict) or isinstance(data, list):
            data = json.dumps(data).encode()
        elif isinstance(data, str):
            data = data.encode()
            
        # Invia i dati
        self.connection.send(data)
    
    def receive_data(self, buffer_size=4096):
        """Riceve dati dalla connessione"""
        if not self.connection:
            raise ValueError("Connessione non stabilita")
            
        data = self.connection.recv(buffer_size)
        
        try:
            # Prova a decodificare i dati come JSON
            return json.loads(data)
        except:
            # Altrimenti restituisce i dati come stringa
            return data.decode()
    
    def close(self):
        """Chiude la connessione"""
        if self.connection:
            self.connection.close()
            self.connection = None

class TLSClientHandler:
    """Gestisce una connessione client in un server TLS"""
    def __init__(self, connection, address):
        self.connection = connection
        self.address = address
    
    def send_data(self, data):
        """Invia dati al client"""
        # Converte i dati in JSON se necessario
        if isinstance(data, dict) or isinstance(data, list):
            data = json.dumps(data).encode()
        elif isinstance(data, str):
            data = data.encode()
            
        # Invia i dati
        self.connection.send(data)
    
    def receive_data(self, buffer_size=4096):
        """Riceve dati dal client"""
        data = self.connection.recv(buffer_size)
        
        try:
            # Prova a decodificare i dati come JSON
            return json.loads(data)
        except:
            # Altrimenti restituisce i dati come stringa
            return data.decode()
    
    def close(self):
        """Chiude la connessione con il client"""
        self.connection.close()

def create_temporary_cert_for_testing():
    """
    Crea un certificato temporaneo per i test
    
    Returns:
        tuple: (cert_file, key_file)
    """
    # Crea file temporanei per certificato e chiave
    cert_file = tempfile.NamedTemporaryFile(delete=False)
    key_file = tempfile.NamedTemporaryFile(delete=False)
    
    # Genera una chiave privata RSA
    os.system(f"openssl genrsa -out {key_file.name} 2048")
    
    # Genera un certificato self-signed
    os.system(f"openssl req -new -key {key_file.name} -out /tmp/cert.csr -subj '/CN=localhost'")
    os.system(f"openssl x509 -req -days 365 -in /tmp/cert.csr -signkey {key_file.name} -out {cert_file.name}")
    
    # Chiudi i file temporanei
    cert_file.close()
    key_file.close()
    
    return cert_file.name, key_file.name

# Esempio di utilizzo:
if __name__ == "__main__":
    # Crea certificati temporanei per i test
    server_cert, server_key = create_temporary_cert_for_testing()
    client_cert, client_key = create_temporary_cert_for_testing()
    
    # Avvia un server in un processo separato
    import threading
    
    def run_server():
        server = TLSConnection("localhost", 12345, server_cert, server_key, 
                              ca_cert=client_cert, is_server=True)
        
        for client in server.start_server():
            data = client.receive_data()
            print(f"Server ricevuto: {data}")
            client.send_data({"status": "ok", "message": "Hello from server"})
            client.close()
    
    server_thread = threading.Thread(target=run_server)
    server_thread.daemon = True
    server_thread.start()
    
    # Attendi che il server sia pronto
    import time
    time.sleep(1)
    
    # Connetti un client
    client = TLSConnection("localhost", 12345, client_cert, client_key, 
                           ca_cert=server_cert, is_server=False)
    
    try:
        client.connect()
        client.send_data({"message": "Hello from client"})
        response = client.receive_data()
        print(f"Client ricevuto: {response}")
    finally:
        client.close()
        
    # Pulisci i file temporanei
    import os
    os.unlink(server_cert)
    os.unlink(server_key)
    os.unlink(client_cert)
    os.unlink(client_key)